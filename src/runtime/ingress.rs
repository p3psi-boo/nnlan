//! Bounded, flow-isolated queue BEFORE link admission. Keep draining the TUN
//! ring instead of hiding a standing FIFO behind a blocked destination.
//! Byte-based DRR/new-flow scheduling; hard limits evict from the fattest
//! bucket so a saturated bulk flow does not globally tail-drop new short flows.
use serde::Serialize;
use std::{
    collections::{VecDeque, hash_map::RandomState},
    hash::{BuildHasher, Hasher},
    time::{Duration, Instant},
};

pub(super) const FLOWS: usize = 256;
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_PACKETS: usize = 32768;
// This pre-admission lifetime accommodates high-BDP bursts. The existing
// post-admission source queue still has its separate 250 ms deadline.
const LIFETIME: Duration = Duration::from_millis(500);

#[derive(Default, Serialize)]
pub(super) struct Stats {
    pub pauses: u64,
    pub expired_packets: u64,
    pub max_wait_us: u64,
    pub overflow_dropped: u64,
    pub queued_bytes: usize,
    pub queued_packets: usize,
    pub active_flows: usize,
}
impl Stats {
    pub fn dropped(&self) -> u64 {
        self.expired_packets + self.overflow_dropped
    }
}

pub(super) struct Packet {
    pub bytes: Vec<u8>,
    bucket: usize,
    at: Instant,
}
#[derive(Default)]
struct Flow {
    packets: VecDeque<Packet>,
    bytes: usize,
    deficit: i64,
    active: bool,
}

pub(super) struct Ingress {
    flows: Vec<Flow>,
    new: VecDeque<usize>,
    old: VecDeque<usize>,
    hash: RandomState,
    quantum: usize,
    pub stats: Stats,
}
impl Ingress {
    pub fn new(mtu: u16) -> Self {
        Self {
            flows: (0..FLOWS).map(|_| Flow::default()).collect(),
            new: VecDeque::new(),
            old: VecDeque::new(),
            hash: RandomState::new(),
            quantum: usize::from(mtu),
            stats: Stats::default(),
        }
    }
    fn bucket(&self, packet: &[u8]) -> usize {
        let mut hash = self.hash.build_hasher();
        // Ordinary TCP/UDP: five tuple. Fragments/extension headers stay in a
        // conservative address/protocol bucket, never use payload as ports.
        match packet.first().map(|b| b >> 4) {
            Some(4) if packet.len() >= 20 => {
                hash.write(&packet[12..20]);
                hash.write_u8(packet[9]);
                let h = usize::from(packet[0] & 15) * 4;
                let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0;
                if !fragment && matches!(packet[9], 6 | 17) && h >= 20 && packet.len() >= h + 4 {
                    hash.write(&packet[h..h + 4]);
                }
            }
            Some(6) if packet.len() >= 40 => {
                hash.write(&packet[8..40]);
                hash.write_u8(packet[6]);
                if matches!(packet[6], 6 | 17) && packet.len() >= 44 {
                    hash.write(&packet[40..44]);
                }
            }
            _ => hash.write_u8(0), // Normal IP validation still runs before forwarding.
        }
        hash.finish() as usize % FLOWS
    }
    fn remove(&mut self, id: usize) -> Option<Packet> {
        let flow = &mut self.flows[id];
        let packet = flow.packets.pop_front()?;
        flow.bytes -= packet.bytes.len();
        self.stats.queued_bytes -= packet.bytes.len();
        self.stats.queued_packets -= 1;
        Some(packet)
    }
    pub fn enqueue(&mut self, bytes: &[u8], now: Instant) {
        if bytes.is_empty() || bytes.len() > self.quantum {
            self.stats.overflow_dropped += 1;
            return;
        }
        let id = self.bucket(bytes);
        while self.stats.queued_bytes + bytes.len() > MAX_BYTES
            || self.stats.queued_packets >= MAX_PACKETS
        {
            // Rare hard-limit fallback: evict the fattest bucket, not the new
            // sparse flow. Hash collisions share both service and this bound.
            let fattest = (0..FLOWS).max_by_key(|&i| self.flows[i].bytes).unwrap();
            self.remove(fattest)
                .expect("nonempty overflowing scheduler");
            self.stats.overflow_dropped += 1;
        }
        let flow = &mut self.flows[id];
        if !flow.active {
            flow.active = true;
            flow.deficit = self.quantum as i64;
            self.new.push_back(id);
            self.stats.active_flows += 1;
        }
        flow.bytes += bytes.len();
        flow.packets.push_back(Packet {
            bytes: bytes.to_vec(),
            bucket: id,
            at: now,
        });
        self.stats.queued_bytes += bytes.len();
        self.stats.queued_packets += 1;
    }
    pub fn is_empty(&self) -> bool {
        self.stats.queued_packets == 0
    }
    pub fn dequeue(&mut self, now: Instant, blocked: &[bool; FLOWS]) -> Option<Packet> {
        let mut skipped = 0;
        // Bounded scheduler work, including deficit/empty-bucket rotations.
        for _ in 0..FLOWS * 4 {
            let is_new = !self.new.is_empty();
            let id = *if is_new {
                self.new.front()
            } else {
                self.old.front()
            }?;
            let flow = &mut self.flows[id];
            if flow.packets.is_empty() {
                if is_new {
                    self.new.pop_front();
                    self.old.push_back(id);
                } else {
                    self.old.pop_front();
                    flow.active = false;
                    // Do not retain a past bulk flow's large metadata ring in
                    // each of the 256 idle buckets. Keep small rings reusable.
                    if flow.packets.capacity() > 128 {
                        flow.packets = VecDeque::new();
                    }
                    self.stats.active_flows -= 1;
                }
                continue;
            }
            if blocked[id] || flow.deficit <= 0 {
                if flow.deficit <= 0 {
                    flow.deficit += self.quantum as i64;
                }
                if is_new {
                    self.new.pop_front();
                } else {
                    self.old.pop_front();
                }
                self.old.push_back(id);
                if blocked[id] {
                    skipped += 1;
                    if skipped >= self.new.len() + self.old.len() {
                        return None;
                    }
                }
                continue;
            }
            let packet = self.remove(id).expect("nonempty scheduled bucket");
            let age = now.saturating_duration_since(packet.at);
            self.stats.max_wait_us = self
                .stats
                .max_wait_us
                .max(age.as_micros().min(u128::from(u64::MAX)) as u64);
            if age >= LIFETIME {
                self.stats.expired_packets += 1;
                continue;
            }
            let flow = &mut self.flows[id];
            flow.deficit -= packet.bytes.len() as i64;
            return Some(packet);
        }
        None
    }
    pub fn defer(&mut self, packet: Packet, blocked: &mut [bool; FLOWS]) {
        let id = packet.bucket;
        blocked[id] = true;
        let flow = &mut self.flows[id];
        flow.deficit += packet.bytes.len() as i64;
        flow.bytes += packet.bytes.len();
        self.stats.queued_bytes += packet.bytes.len();
        self.stats.queued_packets += 1;
        self.stats.pauses += 1;
        flow.packets.push_front(packet); // Preserve FIFO and original sojourn clock.
    }
}

#[cfg(test)]
mod tests;
