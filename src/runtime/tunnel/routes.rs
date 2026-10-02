//! Narrow rtnetlink client for this TUN's host routes, not a routing manager.
use anyhow::{Context, Result, ensure};
use nix::sys::{
    socket::{
        self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, sockopt,
    },
    time::TimeVal,
};
use std::{
    io,
    net::IpAddr,
    os::fd::{AsRawFd, OwnedFd},
};

// Linux UAPI enum RTAX_ADVMSS; libc exposes RTA_METRICS, not this nested ID.
const RTAX_ADVMSS: u16 = 8;

/// Prefer one link source frame for local peer TCP traffic. TUN MTU stays
/// unchanged; small-PMTU hops and large UDP packets still use fragmentation.
fn advertised_mss(address: IpAddr, mtu: u16) -> u32 {
    use crate::transport::{link::frame, wire};
    let inner_ip = frame::FRAGMENT_BYTES - wire::ENVELOPE_HEADER - 1;
    (inner_ip.min(usize::from(mtu)) - if address.is_ipv4() { 40 } else { 60 }) as u32
}

pub(super) struct HostRoutes {
    socket: OwnedFd,
    interface: u32,
    sequence: u32,
    mtu: u16,
}

impl HostRoutes {
    pub(super) fn open(name: &str, mtu: u16) -> Result<Self> {
        let interface = nix::net::if_::if_nametoindex(name)?;
        let socket = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )?;
        socket::bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
        // One request in flight, no subscriptions, no subprocesses. A missing
        // ACK is fatal rather than silently recording an uninstalled route.
        socket::setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::new(2, 0))?;
        socket::setsockopt(&socket, sockopt::SendTimeout, &TimeVal::new(2, 0))?;
        Ok(Self {
            socket,
            interface,
            sequence: 0,
            mtu,
        })
    }

    pub(super) fn change(&mut self, address: IpAddr, add: bool) -> Result<()> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let request = request(address, self.interface, self.sequence, add, self.mtu);
        let sent = socket::sendto(
            self.socket.as_raw_fd(),
            &request,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?;
        ensure!(sent == request.len(), "short route request");
        let mut response = [0; 4096];
        let (length, sender) =
            socket::recvfrom::<NetlinkAddr>(self.socket.as_raw_fd(), &mut response)
                .context("receive route ACK")?;
        ensure!(
            sender.is_some_and(|a| a.pid() == 0 && a.groups() == 0),
            "route ACK not from kernel"
        );
        acknowledge(&response[..length], &request).with_context(|| {
            format!(
                "{} TUN host route {address}",
                if add { "add" } else { "delete" }
            )
        })
    }
}

fn attribute(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    message.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(message.len().next_multiple_of(4), 0);
}

fn request(address: IpAddr, interface: u32, sequence: u32, add: bool, mtu: u16) -> Vec<u8> {
    let mut message = vec![0; 16]; // nlmsghdr, then rtmsg (12 bytes).
    let kind = if add {
        libc::RTM_NEWROUTE
    } else {
        libc::RTM_DELROUTE
    };
    let flags = libc::NLM_F_REQUEST
        | libc::NLM_F_ACK
        | if add {
            libc::NLM_F_CREATE | libc::NLM_F_EXCL
        } else {
            0
        };
    message[4..6].copy_from_slice(&kind.to_ne_bytes());
    message[6..8].copy_from_slice(&(flags as u16).to_ne_bytes());
    message[8..12].copy_from_slice(&sequence.to_ne_bytes());
    let (family, prefix, scope) = if address.is_ipv4() {
        (libc::AF_INET, 32, libc::RT_SCOPE_LINK)
    } else {
        (libc::AF_INET6, 128, libc::RT_SCOPE_UNIVERSE)
    };
    message.extend_from_slice(&[
        family as u8,
        prefix,
        0,
        0,
        libc::RT_TABLE_MAIN,
        libc::RTPROT_BOOT,
        scope,
        libc::RTN_UNICAST,
        0,
        0,
        0,
        0,
    ]);
    match address {
        IpAddr::V4(a) => attribute(&mut message, libc::RTA_DST, &a.octets()),
        IpAddr::V6(a) => attribute(&mut message, libc::RTA_DST, &a.octets()),
    }
    attribute(&mut message, libc::RTA_OIF, &interface.to_ne_bytes());
    if address.is_ipv6() {
        // Match `ip -6 route add PREFIX dev TUN`'s default metric.
        attribute(&mut message, libc::RTA_PRIORITY, &1024u32.to_ne_bytes());
    }
    if add {
        let mut metrics = Vec::new();
        attribute(
            &mut metrics,
            RTAX_ADVMSS,
            &advertised_mss(address, mtu).to_ne_bytes(),
        );
        attribute(&mut message, libc::RTA_METRICS, &metrics);
    }
    let length = message.len() as u32;
    message[..4].copy_from_slice(&length.to_ne_bytes());
    message
}

fn acknowledge(response: &[u8], request: &[u8]) -> Result<()> {
    ensure!(response.len() >= 36, "truncated route ACK");
    let length = u32::from_ne_bytes(response[..4].try_into()?) as usize;
    ensure!(length == response.len(), "invalid route ACK length");
    ensure!(
        u16::from_ne_bytes(response[4..6].try_into()?) == libc::NLMSG_ERROR as u16,
        "unexpected route response"
    );
    ensure!(
        response[8..12] == request[8..12] && response[20..36] == request[..16],
        "route ACK request mismatch"
    );
    let error = i32::from_ne_bytes(response[16..20].try_into()?);
    ensure!((-4095..=0).contains(&error), "invalid route ACK errno");
    if error != 0 {
        return Err(io::Error::from_raw_os_error(-error).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_mss_never_exceeds_tun_or_link_payload_capacity() {
        for mtu in [1280, 1300, 1420, 9000] {
            for raw in ["33.1.2.3", "fd33::123"] {
                let address: IpAddr = raw.parse().unwrap();
                let headers = if address.is_ipv4() { 40 } else { 60 };
                let inner_ip = advertised_mss(address, mtu) + headers;
                assert_eq!(inner_ip, u32::from(mtu).min(1303));
            }
        }
    }

    #[test]
    fn advertised_mss_fits_one_source_frame_without_nested_ciphertext() {
        use crate::{
            identity::test_id,
            reliability::fec::FecScope,
            transport::{
                link::{
                    Controller, Link, Message,
                    frame::{DATAGRAM_OVERHEAD, Fragment, Frame},
                },
                wire,
            },
        };
        for address in ["33.1.2.3", "fd33::123"] {
            let address: IpAddr = address.parse().unwrap();
            let mss = advertised_mss(address, 1420) as usize;
            assert_eq!(mss, if address.is_ipv4() { 1263 } else { 1243 });
            let ip_bytes = mss + if address.is_ipv4() { 40 } else { 60 };
            for extra in [0, 1] {
                let now = std::time::Instant::now();
                let mut control = Controller::new(10_000_000, now);
                let mut link = Link::new(
                    FecScope {
                        peer: test_id(1),
                        path_epoch: 1,
                        key_epoch: 1,
                        direction: 0,
                    },
                    now,
                    Default::default(),
                );
                link.enqueue(
                    Message {
                        kind: 2,
                        payload: vec![0; wire::ENVELOPE_HEADER + 1 + ip_bytes + extra],
                    },
                    now,
                    &control,
                )
                .unwrap();
                let packet = link.poll_one(now, &mut control).unwrap().unwrap();
                assert_eq!(packet.len() + DATAGRAM_OVERHEAD, wire::MAX_UDP);
                let Frame::Source { shard, .. } = Frame::decode(&packet).unwrap() else {
                    panic!("source frame")
                };
                assert_eq!(Fragment::decode(&shard).unwrap().count, 1 + extra);
            }
        }
    }

    #[test]
    #[ignore = "run via tests/e2e/tun_routes_netns.py in its owned namespace"]
    fn kernel_host_routes_preserve_conflicts_and_acknowledge_changes() {
        assert_eq!(
            std::env::var("NNLAN_ROUTE_TEST_NETNS").as_deref(),
            Ok("owned")
        );
        fn ip(args: &[&str]) -> Vec<serde_json::Value> {
            let output = std::process::Command::new("ip")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{:?}: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
            if output.stdout.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&output.stdout).unwrap()
            }
        }
        let mut routes = HostRoutes::open("ggtest0", 1280).unwrap();
        for (family, address, prefix) in [
            ("-4", "33.250.0.1", "33.250.0.1/32"),
            ("-6", "fd33::ff01", "fd33::ff01/128"),
        ] {
            let address = address.parse().unwrap();
            ip(&[family, "route", "add", prefix, "dev", "ggother0"]);
            assert!(
                routes.change(address, true).is_err(),
                "must not replace an existing route"
            );
            assert!(
                routes.change(address, false).is_err(),
                "must not delete another interface's route"
            );
            let existing = ip(&[family, "-j", "route", "show", "exact", prefix]);
            assert_eq!(existing.len(), 1);
            assert_eq!(existing[0]["dev"], "ggother0");
            ip(&[family, "route", "del", prefix, "dev", "ggother0"]);
            routes.change(address, true).unwrap();
            assert!(routes.change(address, true).is_err());
            let installed = ip(&[
                family, "-j", "route", "show", "exact", prefix, "proto", "boot",
            ]);
            assert_eq!(installed.len(), 1);
            assert_eq!(installed[0]["dev"], "ggtest0");
            assert_eq!(
                installed[0]["metrics"][0]["advmss"],
                advertised_mss(address, 1280)
            );
            if family == "-6" {
                assert_eq!(installed[0]["metric"], 1024);
            }
            routes.change(address, false).unwrap();
            assert!(ip(&[family, "-j", "route", "show", "exact", prefix]).is_empty());
            assert!(routes.change(address, false).is_err());
        }
        let start = std::time::Instant::now();
        let addresses: Vec<IpAddr> = (1..=1000u32)
            .flat_map(|n| {
                [
                    std::net::Ipv4Addr::from(0x21fb0000 + n).into(),
                    std::net::Ipv6Addr::from((0xfd33u128 << 112) + n as u128).into(),
                ]
            })
            .collect();
        for &address in &addresses {
            routes.change(address, true).unwrap();
        }
        assert_eq!(
            ip(&["-4", "-j", "route", "show", "dev", "ggtest0"]).len(),
            1000
        );
        assert_eq!(
            ip(&[
                "-6", "-j", "route", "show", "dev", "ggtest0", "proto", "boot"
            ])
            .len(),
            1000
        );
        for &address in &addresses {
            routes.change(address, false).unwrap();
        }
        println!(
            "2000 dual-stack host routes added/deleted with ACKs in {:?}",
            start.elapsed()
        );
        // The background writer reports readiness only after real kernel ACKs.
        use super::super::worker::RouteWorker;
        let worker = RouteWorker::open("ggtest0", 1280).unwrap();
        let wait = || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !worker.ready().unwrap() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        };
        worker.replace(addresses.iter().copied().collect()).unwrap();
        wait();
        for family in ["-4", "-6"] {
            assert_eq!(
                ip(&[
                    family, "-j", "route", "show", "dev", "ggtest0", "proto", "boot"
                ])
                .len(),
                1000
            );
        }
        worker.replace(Default::default()).unwrap();
        wait();
        for family in ["-4", "-6"] {
            assert!(
                ip(&[
                    family, "-j", "route", "show", "dev", "ggtest0", "proto", "boot"
                ])
                .is_empty()
            );
        }
        println!("background writer: 2000 acknowledged dual-stack routes added/deleted");
    }

    #[test]
    fn dual_stack_host_routes_are_exclusive_and_interface_bound() {
        for address in ["33.1.2.3", "fd33::123"] {
            let address: IpAddr = address.parse().unwrap();
            let add = request(address, 17, 42, true, 1280);
            assert_eq!(
                u32::from_ne_bytes(add[..4].try_into().unwrap()) as usize,
                add.len()
            );
            assert_eq!(add[17], if address.is_ipv4() { 32 } else { 128 });
            assert_eq!(
                &add[20..24],
                &[
                    libc::RT_TABLE_MAIN,
                    libc::RTPROT_BOOT,
                    if address.is_ipv4() {
                        libc::RT_SCOPE_LINK
                    } else {
                        libc::RT_SCOPE_UNIVERSE
                    },
                    libc::RTN_UNICAST
                ]
            );
            let flags = u16::from_ne_bytes(add[6..8].try_into().unwrap()) as i32;
            assert_eq!(
                flags,
                libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL
            );
            let dst_len = if address.is_ipv4() { 4 } else { 16 };
            let oif = 28 + 4 + dst_len;
            assert_eq!(&add[oif + 4..oif + 8], &17u32.to_ne_bytes());
            let del = request(address, 17, 43, false, 1280);
            assert_eq!(
                u16::from_ne_bytes(del[4..6].try_into().unwrap()),
                libc::RTM_DELROUTE
            );
            assert_eq!(&add[16..del.len()], &del[16..]);
            let metrics = &add[del.len()..];
            assert_eq!(metrics.len(), 12);
            assert_eq!(&metrics[2..4], &libc::RTA_METRICS.to_ne_bytes());
            assert_eq!(&metrics[6..8], &(RTAX_ADVMSS).to_ne_bytes());
            assert_eq!(&metrics[8..], &advertised_mss(address, 1280).to_ne_bytes());
            assert_eq!(
                u16::from_ne_bytes(del[6..8].try_into().unwrap()) as i32,
                libc::NLM_F_REQUEST | libc::NLM_F_ACK
            );
        }
    }

    #[test]
    fn ack_must_match_request_and_propagate_kernel_errors() {
        let request = request("33.1.2.3".parse().unwrap(), 17, 42, true, 1280);
        let mut ack = vec![0; 36];
        ack[..4].copy_from_slice(&36u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        ack[8..12].copy_from_slice(&request[8..12]);
        ack[20..].copy_from_slice(&request[..16]);
        assert!(acknowledge(&ack, &request).is_ok());
        for len in 0..36 {
            assert!(acknowledge(&ack[..len], &request).is_err());
        }
        for offset in [0, 4, 8, 20, 24, 28] {
            let mut bad = ack.clone();
            bad[offset] ^= 1;
            assert!(acknowledge(&bad, &request).is_err());
        }
        ack[16..20].copy_from_slice(&(-libc::EEXIST).to_ne_bytes());
        let error = acknowledge(&ack, &request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EEXIST)
        );
        ack[16..20].copy_from_slice(&i32::MIN.to_ne_bytes());
        assert!(acknowledge(&ack, &request).is_err());
    }
}
