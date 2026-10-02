//! Preserve a wildcard socket's actual destination as the reply source.
//! No per-address sockets, global untrusted endpoint cache, or unsafe code.
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
use std::{
    io::{self, IoSlice},
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};
use tokio::{io::Interest, net::UdpSocket};

mod receive;
pub(super) use receive::Receiver;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Source {
    ip: IpAddr,
    scope: u32,
}

pub(super) fn enable(socket: &socket2::Socket, ipv6: bool) -> io::Result<()> {
    use nix::sys::socket::{setsockopt, sockopt};
    setsockopt(socket, sockopt::Ipv4PacketInfo, &true)?;
    if ipv6 {
        setsockopt(socket, sockopt::Ipv6RecvPacketInfo, &true)?;
    }
    // GRO is an optional local optimization, never a negotiated wire feature.
    match setsockopt(socket, sockopt::UdpGroSegment, &true) {
        Ok(())
        | Err(
            nix::errno::Errno::ENOPROTOOPT
            | nix::errno::Errno::EINVAL
            | nix::errno::Errno::EOPNOTSUPP,
        ) => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(super) async fn send(
    socket: &UdpSocket,
    bytes: &[u8],
    endpoint: SocketAddr,
    local: Option<Source>,
) -> io::Result<usize> {
    let Some(local) = local else {
        return socket.send_to(bytes, endpoint).await;
    };
    socket
        .async_io(Interest::WRITABLE, || {
            let target = SockaddrStorage::from(endpoint);
            let iov = [IoSlice::new(bytes)];
            let result = match local.ip {
                IpAddr::V4(ip) => {
                    let info = libc::in_pktinfo {
                        // Pin the local address, not the ingress NIC: asymmetric routes
                        // and a changed default gateway still use the kernel's route.
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(ip.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    sendmsg(
                        socket.as_raw_fd(),
                        &iov,
                        &[ControlMessage::Ipv4PacketInfo(&info)],
                        MsgFlags::MSG_DONTWAIT,
                        Some(&target),
                    )
                }
                IpAddr::V6(ip) => {
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: ip.octets(),
                        },
                        ipi6_ifindex: local.scope,
                    };
                    sendmsg(
                        socket.as_raw_fd(),
                        &iov,
                        &[ControlMessage::Ipv6PacketInfo(&info)],
                        MsgFlags::MSG_DONTWAIT,
                        Some(&target),
                    )
                }
            };
            result.map_err(Into::into)
        })
        .await
}

/// Only already paced, individually encrypted datagrams enter this bounded batch.
/// Datagram boundaries, destination addresses and source-affinity cmsgs are preserved.
pub(super) struct Datagram {
    pub bytes: Vec<u8>,
    pub endpoint: SocketAddr,
    pub local: Option<Source>,
    pub gso: bool,
}
pub(super) const SEND_BATCH: usize = 32;

/// Send a FIFO prefix with Linux UDP segmentation offload. Each segment is an
/// independently authenticated wire datagram; no padding or packet reordering.
/// A successful sendmsg accepts the entire aggregate (unlike sendmmsg).
pub(super) async fn send_batch(
    socket: &UdpSocket,
    packets: &[Datagram],
    gso: bool,
) -> io::Result<usize> {
    let Some(first) = packets.first() else {
        return Ok(0);
    };
    let segment = first.bytes.len();
    let mut count = 1;
    if gso && first.gso && segment > 0 && segment <= u16::MAX as usize / SEND_BATCH {
        for p in packets.iter().take(SEND_BATCH).skip(1) {
            if !p.gso
                || p.local != first.local
                || p.endpoint != first.endpoint
                || p.bytes.is_empty()
                || p.bytes.len() > segment
            {
                break;
            }
            count += 1;
            // Only the final segment may be shorter than the GSO size.
            if p.bytes.len() < segment {
                break;
            }
        }
    }
    if count == 1 {
        send(socket, &first.bytes, first.endpoint, first.local).await?;
        return Ok(1);
    }
    let iov: Vec<_> = packets[..count]
        .iter()
        .map(|p| IoSlice::new(&p.bytes))
        .collect();
    socket
        .async_io(Interest::WRITABLE, || {
            let target = SockaddrStorage::from(first.endpoint);
            let segment = segment as u16;
            let v4;
            let v6;
            let mut control = vec![ControlMessage::UdpGsoSegments(&segment)];
            match first.local {
                Some(Source {
                    ip: IpAddr::V4(ip), ..
                }) => {
                    v4 = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(ip.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    control.push(ControlMessage::Ipv4PacketInfo(&v4));
                }
                Some(Source {
                    ip: IpAddr::V6(ip),
                    scope,
                }) => {
                    v6 = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: ip.octets(),
                        },
                        ipi6_ifindex: scope,
                    };
                    control.push(ControlMessage::Ipv6PacketInfo(&v6));
                }
                None => (),
            }
            sendmsg(
                socket.as_raw_fd(),
                &iov,
                &control,
                MsgFlags::MSG_DONTWAIT,
                Some(&target),
            )?;
            Ok(count)
        })
        .await
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[tokio::test]
    async fn receive_bursts_preserve_source_and_rearm_after_empty() {
        let raw = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        enable(&raw, false).unwrap();
        raw.set_nonblocking(true).unwrap();
        raw.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let receiver = UdpSocket::from_std(raw.into()).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            receiver.local_addr().unwrap().port(),
        );
        let mut buffer = [0; 64];
        let mut reader = Receiver::new();
        // More than two engine batches, with no missing packet at the boundary.
        for index in 0..67u8 {
            sender.send_to(&[index; 17], target).await.unwrap();
        }
        for index in 0..67u8 {
            let (size, from, local) = if index % 32 == 0 {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    reader.recv(&receiver, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap()
            } else {
                reader.try_recv(&receiver, &mut buffer).unwrap()
            };
            assert_eq!(&buffer[..size], &[index; 17]);
            assert_eq!(from, sender.local_addr().unwrap());
            assert_eq!(local.unwrap().ip, target.ip());
        }
        assert_eq!(
            reader.try_recv(&receiver, &mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // EAGAIN must clear Tokio readiness, then a later datagram must wake it.
        let send = async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            sender.send_to(b"again", target).await.unwrap();
        };
        let receive = async {
            let (size, _, _) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                reader.recv(&receiver, &mut buffer),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&buffer[..size], b"again");
        };
        tokio::join!(send, receive);
    }

    #[tokio::test]
    async fn batch_preserves_boundaries_destinations_and_source_affinity() {
        let sender = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = Some(Source {
            ip: "127.0.0.2".parse().unwrap(),
            scope: 0,
        });
        let packets: Vec<_> = (0..4)
            .map(|i| Datagram {
                gso: true,
                bytes: vec![i; 17 + usize::from(i)],
                endpoint: if i % 2 == 0 {
                    first.local_addr().unwrap()
                } else {
                    second.local_addr().unwrap()
                },
                local: if i == 3 { None } else { local },
            })
            .collect();
        for p in &packets {
            assert_eq!(
                send_batch(&sender, std::slice::from_ref(p), true)
                    .await
                    .unwrap(),
                1
            );
        }
        for (receiver, indices) in [(&first, [0, 2]), (&second, [1, 3])] {
            for index in indices {
                let mut bytes = [0; 100];
                let (n, source) = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    receiver.recv_from(&mut bytes),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(bytes[..n], packets[index].bytes);
                assert_eq!(
                    source.ip(),
                    if index == 3 { "127.0.0.1" } else { "127.0.0.2" }
                        .parse::<IpAddr>()
                        .unwrap()
                );
            }
        }
        assert_eq!(send_batch(&sender, &[], true).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn gso_preserves_ipv4_ipv6_and_mapped_datagrams() {
        for (bind, destination, ip) in [
            ("0.0.0.0:0", "127.0.0.1:0", "127.0.0.2"),
            ("[::]:0", "[::1]:0", "::1"),
            ("[::]:0", "127.0.0.1:0", "127.0.0.2"),
        ] {
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
            raw.set_nonblocking(true).unwrap();
            raw.bind(&bind.into()).unwrap();
            let sender = UdpSocket::from_std(raw.into()).unwrap();
            let receiver = UdpSocket::bind(destination).await.unwrap();
            let mut endpoint = receiver.local_addr().unwrap();
            if bind.is_ipv6() && endpoint.is_ipv4() {
                let IpAddr::V4(ip) = endpoint.ip() else {
                    unreachable!()
                };
                endpoint = SocketAddr::new(ip.to_ipv6_mapped().into(), endpoint.port());
            }
            let source = Source {
                ip: ip.parse().unwrap(),
                scope: 0,
            };
            // Equal segments followed by a short final one, then another group.
            let packets: Vec<_> = [1232, 1232, 1232, 79, 1232, 1232, 1232, 0]
                .into_iter()
                .enumerate()
                .map(|(i, size)| Datagram {
                    gso: true,
                    bytes: vec![i as u8; size],
                    endpoint,
                    local: Some(source),
                })
                .collect();
            assert_eq!(send_batch(&sender, &packets, true).await.unwrap(), 4);
            assert_eq!(send_batch(&sender, &packets[4..], true).await.unwrap(), 3);
            assert_eq!(send_batch(&sender, &packets[7..], true).await.unwrap(), 1);
            for p in &packets {
                let mut bytes = [0; 1500];
                let (n, from) = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    receiver.recv_from(&mut bytes),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(bytes[..n], p.bytes);
                assert_eq!(from.ip(), source.ip);
            }
            // Device/kernel fallback sends one normal datagram, never a jumbo UDP.
            assert_eq!(send_batch(&sender, &packets, false).await.unwrap(), 1);
            let mut bytes = [0; 1500];
            let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
            assert_eq!(bytes[..n], packets[0].bytes);
            assert_eq!(
                receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[tokio::test]
    async fn gso_is_bounded_and_stops_at_source_changes() {
        let sender = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packets: Vec<_> = (0..SEND_BATCH + 2)
            .map(|i| Datagram {
                gso: true,
                bytes: vec![i as u8; 128],
                endpoint: receiver.local_addr().unwrap(),
                local: None,
            })
            .collect();
        assert_eq!(
            send_batch(&sender, &packets, true).await.unwrap(),
            SEND_BATCH
        );
        for p in &packets[..SEND_BATCH] {
            let mut bytes = [0; 1500];
            let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
            assert_eq!(bytes[..n], p.bytes);
        }
        // Conservative PMTU fallback is per packet/path, not per socket.
        // Never pull an ineligible packet into a preceding GSO aggregate.
        packets[2].gso = false;
        assert_eq!(send_batch(&sender, &packets, true).await.unwrap(), 2);
        assert_eq!(send_batch(&sender, &packets[2..], true).await.unwrap(), 1);
        for p in &packets[..3] {
            let mut bytes = [0; 1500];
            let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
            assert_eq!(bytes[..n], p.bytes);
        }
        packets[2].gso = true;
        packets[2].local = Some(Source {
            ip: "127.0.0.2".parse().unwrap(),
            scope: 0,
        });
        assert_eq!(send_batch(&sender, &packets, true).await.unwrap(), 2);
        for p in &packets[..2] {
            let mut bytes = [0; 1500];
            let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
            assert_eq!(bytes[..n], p.bytes);
        }
        let mut bytes = [0; 1500];
        assert_eq!(
            receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn batch_stops_before_a_different_destination() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packets = [
            Datagram {
                gso: true,
                bytes: vec![1],
                endpoint: receiver.local_addr().unwrap(),
                local: None,
            },
            Datagram {
                gso: true,
                bytes: vec![2],
                endpoint: "127.0.0.1:0".parse().unwrap(),
                local: None,
            },
        ];
        assert_eq!(send_batch(&sender, &packets, true).await.unwrap(), 1);
        assert!(send_batch(&sender, &packets[1..], true).await.is_err());
        let mut bytes = [0; 2];
        assert_eq!(receiver.recv_from(&mut bytes).await.unwrap().0, 1);
        assert_eq!(bytes[0], 1);
        assert_eq!(
            receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
