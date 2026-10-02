//! Interface notifications are hints: always reconcile from a bounded snapshot.
use super::candidates::{LIMIT, canonical, usable};
use anyhow::{Context, Result, ensure};
use nix::sys::socket::{
    self, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, OwnedFd},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, unix::AsyncFd},
    process::Command,
    sync::mpsc,
    time::{Instant, sleep_until},
};

const RESYNC: Duration = Duration::from_secs(15);
const RETRY: Duration = Duration::from_secs(5);
const COALESCE: Duration = Duration::from_millis(100);

struct Changes(AsyncFd<OwnedFd>);
impl Changes {
    fn open() -> Result<Self> {
        let fd = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )?;
        let groups =
            (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
        socket::bind(fd.as_raw_fd(), &NetlinkAddr::new(0, groups))?;
        Ok(Self(AsyncFd::new(fd)?))
    }
    async fn changed(&self) -> io::Result<()> {
        // No event log or untrusted address cache: even a truncated notification
        // means only "query the kernel again". ENOBUFS requires the same resync.
        let mut buffer = [0; 8192];
        loop {
            let mut ready = self.0.readable().await?;
            match ready.try_io(|fd| {
                match socket::recv(
                    fd.get_ref().as_raw_fd(),
                    &mut buffer,
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(_) | Err(nix::errno::Errno::ENOBUFS) => Ok(()),
                    Err(error) => Err(io::Error::from(error)),
                }
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

fn parse_interfaces(bytes: &[u8], listen: SocketAddr) -> Result<BTreeSet<SocketAddr>> {
    let interfaces: Value = serde_json::from_slice(bytes)?;
    let mut addresses = BTreeSet::new();
    for interface in interfaces.as_array().context("interface list")? {
        if interface["operstate"] == "DOWN" {
            continue;
        }
        for address in interface["addr_info"].as_array().into_iter().flatten() {
            if address["tentative"] == true
                || address["dadfailed"] == true
                || address["preferred_life_time"] == 0
            {
                continue;
            }
            if let Some(ip) = address["local"]
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                let endpoint = canonical(SocketAddr::new(ip, listen.port()));
                if usable(endpoint, listen) && addresses.len() < LIMIT {
                    addresses.insert(endpoint);
                }
            }
        }
    }
    Ok(addresses)
}

pub(super) async fn snapshot(listen: SocketAddr) -> Result<BTreeSet<SocketAddr>> {
    if !listen.ip().is_unspecified() {
        return Ok(BTreeSet::from([listen]));
    }
    let query = async {
        let mut child = Command::new("ip")
            .args(["-j", "address", "show", "up"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("interface snapshot")?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("interface stdout")?
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(bytes.len() <= 1_048_576, "interface snapshot exceeds 1 MiB");
        ensure!(child.wait().await?.success(), "ip address snapshot failed");
        parse_interfaces(&bytes, listen)
    };
    tokio::time::timeout(Duration::from_secs(2), query)
        .await
        .context("interface snapshot timeout")?
}

pub(super) async fn monitor(listen: SocketAddr, tx: mpsc::Sender<BTreeSet<SocketAddr>>) {
    let mut changes: Option<Changes> = None;
    let mut refresh_at = Instant::now();
    let mut retry_at = refresh_at;
    loop {
        tokio::select! {
            // A continuous notification stream must not starve reconciliation.
            biased;
            _ = tx.closed() => return,
            _ = sleep_until(refresh_at) => {
                if listen.ip().is_unspecified() && changes.is_none() && Instant::now() >= retry_at {
                    match Changes::open() {
                        Ok(listener) => changes = Some(listener),
                        Err(error) => eprintln!("candidate interface notifications: {error:#}"),
                    }
                    retry_at = Instant::now() + RETRY;
                }
                // Subscribe before querying, including after every reconnect, so
                // changes during a snapshot remain queued for reconciliation.
                match snapshot(listen).await {
                    Ok(addresses) => if tx.send(addresses).await.is_err() { return; },
                    Err(error) => eprintln!("candidate interface refresh: {error:#}"),
                }
                refresh_at = Instant::now() + if changes.is_some() || !listen.ip().is_unspecified() { RESYNC } else { RETRY };
            }
            event = async {
                match &changes {
                    Some(listener) => listener.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Err(error) = event {
                    eprintln!("candidate interface notifications: {error:#}");
                    changes = None;
                    retry_at = Instant::now() + RETRY;
                }
                // First event starts the debounce, later events do not postpone
                // it. Memory and snapshot concurrency stay constant under churn.
                refresh_at = refresh_at.min(Instant::now() + COALESCE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn notification_wait_is_cancel_safe_and_bounded() {
        let (receiver, sender) = std::os::unix::net::UnixDatagram::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let changes = Changes(AsyncFd::new(receiver.into()).unwrap());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), changes.changed())
                .await
                .is_err()
        );
        // Truncation is fine: notifications trigger a full kernel snapshot, not
        // incremental parsing of addresses from this bounded buffer.
        sender.send(&[1; 16384]).unwrap();
        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), changes.changed())
                .await
                .is_err()
        );
        sender.send(&[2]).unwrap();
        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn fixed_listener_refreshes_without_commands_and_stops_when_closed() {
        let listen = "127.0.0.1:7331".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let worker = tokio::spawn(monitor(listen, tx));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap(),
            Some(BTreeSet::from([listen]))
        );
        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn interface_parser_excludes_overlay_down_and_unready_addresses() {
        let bytes = br#"[
          {"operstate":"UP","addr_info":[{"local":"192.168.1.2"},{"local":"33.1.2.3"},{"local":"fd33::1"},{"local":"fe80::1"},{"local":"fd99::1","tentative":true},{"local":"fd99::2","preferred_life_time":0},{"local":"fd99::3"}]},
          {"operstate":"DOWN","addr_info":[{"local":"192.168.2.2"}]},
          {"operstate":"UNKNOWN","addr_info":[{"local":"127.0.0.1"}]}]"#;
        let addresses = parse_interfaces(bytes, "[::]:7331".parse().unwrap()).unwrap();
        assert_eq!(
            addresses,
            ["192.168.1.2:7331", "[fd99::3]:7331"]
                .map(|a| a.parse().unwrap())
                .into()
        );
        assert_eq!(
            parse_interfaces(bytes, "0.0.0.0:7331".parse().unwrap())
                .unwrap()
                .len(),
            1
        );
        assert!(parse_interfaces(b"{}", "0.0.0.0:7331".parse().unwrap()).is_err());
    }
}
