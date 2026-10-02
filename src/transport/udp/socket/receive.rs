//! Bounded Linux UDP GRO reader. Reuse one allocation and return independent
//! wire datagrams; a scheduling yield preserves the unread aggregate tail.
use super::Source;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};
use std::{
    io::{self, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
};
use tokio::{io::Interest, net::UdpSocket};

struct Batch {
    length: usize,
    segment: usize,
    from: SocketAddr,
    local: Option<Source>,
}

pub(crate) struct Receiver {
    buffer: Box<[u8]>,
    pending: Option<Batch>,
    cursor: usize,
}

impl Receiver {
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![0; 65_536].into_boxed_slice(),
            pending: None,
            cursor: 0,
        }
    }

    fn take(&mut self, out: &mut [u8]) -> (usize, SocketAddr, Option<Source>) {
        let batch = self.pending.as_ref().expect("received batch");
        let end = (self.cursor + batch.segment).min(batch.length);
        let size = end - self.cursor;
        // An oversized individual packet is invalid, not a valid truncated prefix.
        let copied = if size <= out.len() {
            out[..size].copy_from_slice(&self.buffer[self.cursor..end]);
            size
        } else {
            0
        };
        let result = (copied, batch.from, batch.local);
        self.cursor = end;
        if end == batch.length {
            self.pending = None;
        }
        result
    }

    pub(crate) async fn recv(
        &mut self,
        socket: &UdpSocket,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<Source>)> {
        if self.pending.is_none() {
            self.pending = Some(
                socket
                    .async_io(Interest::READABLE, || recv_one(socket, &mut self.buffer))
                    .await?,
            );
            self.cursor = 0;
        }
        Ok(self.take(out))
    }

    pub(crate) fn try_recv(
        &mut self,
        socket: &UdpSocket,
        out: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<Source>)> {
        if self.pending.is_none() {
            self.pending =
                Some(socket.try_io(Interest::READABLE, || recv_one(socket, &mut self.buffer))?);
            self.cursor = 0;
        }
        Ok(self.take(out))
    }
}

fn recv_one(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<Batch> {
    // Both IPv4 and IPv6 packet info can accompany a mapped IPv4 datagram.
    #[repr(align(16))]
    struct Ancillary([u8; 128]);
    let mut control = Ancillary([0; 128]);
    let mut iov = [IoSliceMut::new(buffer)];
    let message = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control.0),
        MsgFlags::MSG_DONTWAIT,
    )?;
    let address = message
        .address
        .ok_or_else(|| io::Error::other("missing UDP source"))?;
    let from = if let Some(v4) = address.as_sockaddr_in() {
        SocketAddr::new(v4.ip().into(), v4.port())
    } else if let Some(v6) = address.as_sockaddr_in6() {
        SocketAddr::V6(SocketAddrV6::new(
            v6.ip(),
            v6.port(),
            v6.flowinfo(),
            v6.scope_id(),
        ))
    } else {
        return Err(io::Error::other("invalid UDP address family"));
    };
    let mut local = None;
    let mut segment = None;
    if let Ok(messages) = message.cmsgs() {
        for message in messages {
            match message {
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    local = Some(Source {
                        ip: Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into(),
                        scope: 0,
                    });
                }
                ControlMessageOwned::Ipv6PacketInfo(info) => {
                    let ip = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                    local = Some(match ip.to_ipv4_mapped() {
                        Some(ip) => Source {
                            ip: ip.into(),
                            scope: 0,
                        },
                        None => Source {
                            ip: ip.into(),
                            scope: if ip.is_unicast_link_local() {
                                info.ipi6_ifindex
                            } else {
                                0
                            },
                        },
                    });
                }
                ControlMessageOwned::UdpGroSegments(size) => {
                    segment = Some(size);
                }
                _ => (),
            }
        }
    }
    // Never reinterpret a truncated aggregate or missing cmsg as a datagram.
    // Deliver an empty invalid wire packet for normal transport drop accounting.
    let truncated = message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let valid_segment = segment.is_none_or(|size| size > 0 && size as usize <= message.bytes);
    let length = if truncated || !valid_segment {
        0
    } else {
        message.bytes
    };
    Ok(Batch {
        length,
        segment: segment.map_or(length.max(1), |s| (s as usize).max(1)),
        from,
        local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::udp::socket::{Datagram, enable, send_batch};
    use std::time::Duration;

    #[test]
    fn aggregate_tail_survives_yields_and_oversize_is_not_a_prefix() {
        let mut reader = Receiver::new();
        reader.buffer[..67].copy_from_slice(&(0..67).collect::<Vec<_>>());
        let from = "127.0.0.1:7".parse().unwrap();
        reader.pending = Some(Batch {
            length: 67,
            segment: 1,
            from,
            local: None,
        });
        let mut out = [0; 2];
        for i in 0..67 {
            assert_eq!(reader.take(&mut out), (1, from, None));
            assert_eq!(out[0], i);
        }
        assert!(reader.pending.is_none());
        reader.cursor = 0;
        reader.pending = Some(Batch {
            length: 67,
            segment: 67,
            from,
            local: None,
        });
        assert_eq!(reader.take(&mut out).0, 0);
        assert!(reader.pending.is_none());
        reader.cursor = 0;
        reader.pending = Some(Batch {
            length: 0,
            segment: 1,
            from,
            local: None,
        });
        assert_eq!(reader.take(&mut out).0, 0);
        assert!(reader.pending.is_none());
    }

    #[tokio::test]
    async fn gro_and_fallback_preserve_datagrams_and_dual_stack_packet_info() {
        for (bind, destination) in [
            ("0.0.0.0:0", "127.0.0.2"),
            ("[::]:0", "::1"),
            ("[::]:0", "127.0.0.2"),
        ] {
            for gro in [false, true] {
                let bind: SocketAddr = bind.parse().unwrap();
                let raw = socket2::Socket::new(
                    socket2::Domain::for_address(bind),
                    socket2::Type::DGRAM,
                    None,
                )
                .unwrap();
                if bind.is_ipv6() {
                    raw.set_only_v6(false).unwrap();
                }
                enable(&raw, bind.is_ipv6()).unwrap();
                nix::sys::socket::setsockopt(&raw, nix::sys::socket::sockopt::UdpGroSegment, &gro)
                    .unwrap();
                raw.set_nonblocking(true).unwrap();
                raw.bind(&bind.into()).unwrap();
                let receiver = UdpSocket::from_std(raw.into()).unwrap();
                let ip: std::net::IpAddr = destination.parse().unwrap();
                let sender = UdpSocket::bind(if ip.is_ipv4() {
                    "127.0.0.1:0"
                } else {
                    "[::1]:0"
                })
                .await
                .unwrap();
                let endpoint = SocketAddr::new(ip, receiver.local_addr().unwrap().port());
                let packets: Vec<_> = [1232, 1232, 1232, 59]
                    .into_iter()
                    .enumerate()
                    .map(|(i, size)| Datagram {
                        bytes: vec![i as u8; size],
                        endpoint,
                        local: None,
                        gso: true,
                    })
                    .collect();
                assert_eq!(send_batch(&sender, &packets, true).await.unwrap(), 4);
                let mut reader = Receiver::new();
                let mut out = [0; 1233];
                for (i, packet) in packets.iter().enumerate() {
                    let (n, from, local) = tokio::time::timeout(
                        Duration::from_secs(1),
                        reader.recv(&receiver, &mut out),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert_eq!(&out[..n], packet.bytes);
                    assert_eq!(
                        crate::transport::udp::canonical_address(from),
                        sender.local_addr().unwrap()
                    );
                    assert_eq!(local.unwrap().ip, ip);
                    if i == 0 && gro {
                        assert!(reader.pending.is_some(), "exercise actual GRO aggregation");
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(
                    reader.try_recv(&receiver, &mut out).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                // A jumbo normal datagram and a zero-length datagram both remain invalid,
                // never accidentally interpreted as several authenticated packets.
                sender.send_to(&[5; 2000], endpoint).await.unwrap();
                assert_eq!(reader.recv(&receiver, &mut out).await.unwrap().0, 0);
                sender.send_to(&[], endpoint).await.unwrap();
                assert_eq!(reader.recv(&receiver, &mut out).await.unwrap().0, 0);
            }
        }
    }
}
