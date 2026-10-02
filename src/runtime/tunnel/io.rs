//! Bounded Linux TUN offload adapter. GSO exists only at the kernel boundary;
//! every segment still enters normal routing, authentication and per-link FEC.
use std::io;
use tun_rs::{AsyncDevice, GROTable, VIRTIO_NET_HDR_LEN};

const READ_BATCH: usize = 128;
const WRITE_BATCH: usize = 32;
pub(crate) struct Reader {
    original: Vec<u8>,
    packets: Vec<Vec<u8>>,
    sizes: [usize; READ_BATCH],
    next: usize,
    count: usize,
}
impl Reader {
    pub fn new(mtu: u16) -> Self {
        Self {
            original: vec![0; VIRTIO_NET_HDR_LEN + 65_535],
            packets: vec![vec![0; usize::from(mtu)]; READ_BATCH],
            sizes: [0; READ_BATCH],
            next: 0,
            count: 0,
        }
    }
    pub async fn ready(&mut self, device: &AsyncDevice) -> io::Result<()> {
        if self.next == self.count {
            self.count = device
                .recv_multiple(&mut self.original, &mut self.packets, &mut self.sizes, 0)
                .await?;
            self.next = 0;
        }
        Ok(())
    }
    pub fn try_ready(&mut self, device: &AsyncDevice) -> io::Result<()> {
        if self.next == self.count {
            // AsyncDevice's deref exposes the same nonblocking fd. On EAGAIN
            // the next async ready() clears/re-arms readiness through tokio.
            self.count = tun_rs::DeviceImpl::recv_multiple(
                device,
                &mut self.original,
                &mut self.packets,
                &mut self.sizes,
                0,
            )?;
            self.next = 0;
        }
        Ok(())
    }
    pub fn next(&mut self) -> Option<&[u8]> {
        if self.next == self.count {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(&self.packets[index][..self.sizes[index]])
    }
}

pub(super) struct Writer {
    gro: GROTable,
    capacity: usize,
    packets: Vec<Vec<u8>>,
    count: usize,
}
impl Writer {
    pub fn new(mtu: u16) -> Self {
        Self {
            gro: GROTable::new(),
            capacity: (WRITE_BATCH * usize::from(mtu)).min(65_535) + 2 * VIRTIO_NET_HDR_LEN,
            packets: vec![Vec::new(); WRITE_BATCH],
            count: 0,
        }
    }
    pub async fn send(&mut self, device: &AsyncDevice, packet: &[u8]) -> io::Result<()> {
        if self.count == WRITE_BATCH {
            self.flush(device).await?;
        }
        self.push(packet);
        Ok(())
    }
    fn push(&mut self, packet: &[u8]) {
        let out = &mut self.packets[self.count];
        out.clear();
        // tun-rs never grows a GRO destination beyond its existing capacity.
        // Reserve lazily, once per slot; reserving only one MTU silently turns
        // every coalescing attempt into the single-packet fallback.
        if out.capacity() < self.capacity {
            out.reserve_exact(self.capacity);
        }
        out.resize(VIRTIO_NET_HDR_LEN, 0);
        out.extend_from_slice(packet);
        self.count += 1;
    }
    pub async fn flush(&mut self, device: &AsyncDevice) -> io::Result<()> {
        if self.count == 0 {
            return Ok(());
        }
        let count = std::mem::take(&mut self.count);
        // send_multiple retries each write on EAGAIN internally. Never retry
        // the entire mutated GRO batch after a partial delivery/error.
        device
            .send_multiple(
                &mut self.gro,
                &mut self.packets[..count],
                VIRTIO_NET_HDR_LEN,
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
