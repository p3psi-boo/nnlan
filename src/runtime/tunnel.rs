//! Linux TUN and only per-node host routes; subnet/exit policy is integrated separately.
use crate::{address::AddressCandidate, config::TunConfig};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, net::IpAddr, process::Command};
mod io;
pub(super) use io::Reader;
mod routes;
mod worker;
use worker::RouteWorker;

pub struct Tunnel {
    pub device: tun_rs::AsyncDevice,
    writer: io::Writer,
    name: String,
    address: AddressCandidate,
    routes: Option<RouteWorker>,
}
fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .context("run iproute2")?;
    ensure!(
        output.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
impl Tunnel {
    pub fn create(config: &TunConfig, address: AddressCandidate) -> Result<Self> {
        // Do not take over an existing interface, even when its name matches.
        let existing = Command::new("ip")
            .args(["link", "show", "dev", &config.name])
            .output()?;
        ensure!(!existing.status.success(), "TUN name already exists");
        let build = |offload| {
            tun_rs::DeviceBuilder::new()
                .name(&config.name)
                .ipv4(address.ipv4, 32, None)
                .mtu(config.mtu)
                .offload(offload)
                .enable(true)
                .build_async()
        };
        let mut device = build(true).context("create Linux TUN (CAP_NET_ADMIN required)")?;
        if !device.tcp_gso() {
            // Do not leave IFF_VNET_HDR set when offloads were rejected: plain
            // packet mode must have both the kernel and the adapter agree.
            drop(device);
            device = build(false).context("create plain Linux TUN")?;
        }
        // Bound one kernel aggregate to the reusable reader's capacity, including
        // small-MSS TCP flows. This is segmentation size, not queue enlargement.
        ip(&[
            "link",
            "set",
            "dev",
            &config.name,
            "gso_max_size",
            "65535",
            "gso_max_segs",
            "128",
        ])?;
        ip(&[
            "-6",
            "address",
            "add",
            &format!("{}/128", address.ipv6),
            "dev",
            &config.name,
            "nodad",
        ])?;
        Ok(Self {
            routes: Some(RouteWorker::open(&config.name, config.mtu)?),
            device,
            writer: io::Writer::new(config.mtu),
            name: config.name.clone(),
            address,
        })
    }
    pub async fn send(&mut self, packet: &[u8]) -> std::io::Result<()> {
        self.writer.send(&self.device, packet).await
    }
    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush(&self.device).await
    }
    pub fn address(&mut self, address: AddressCandidate) -> Result<()> {
        if address.ipv4 == self.address.ipv4 {
            return Ok(());
        }
        ip(&[
            "-4",
            "address",
            "add",
            &format!("{}/32", address.ipv4),
            "dev",
            &self.name,
        ])?;
        ip(&[
            "-4",
            "address",
            "del",
            &format!("{}/32", self.address.ipv4),
            "dev",
            &self.name,
        ])?;
        self.address = address;
        Ok(())
    }
    pub fn sync_routes(&mut self, desired: BTreeSet<IpAddr>) -> Result<()> {
        self.routes
            .as_ref()
            .expect("live route worker")
            .replace(desired)
    }
    pub fn routes_ready(&self) -> Result<bool> {
        self.routes.as_ref().expect("live route worker").ready()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Stop the writer before automatic field destruction closes the TUN.
        drop(self.routes.take());
    }
}

pub fn ip_addresses(packet: &[u8]) -> Result<(IpAddr, IpAddr)> {
    ensure!(!packet.is_empty(), "empty IP packet");
    match packet[0] >> 4 {
        4 => {
            ensure!(
                packet.len() >= 20
                    && usize::from(packet[0] & 15) * 4 >= 20
                    && usize::from(packet[0] & 15) * 4 <= packet.len(),
                "IPv4 header length"
            );
            ensure!(
                usize::from(u16::from_be_bytes(packet[2..4].try_into()?)) == packet.len(),
                "IPv4 packet length"
            );
            Ok((
                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16])?).into(),
                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20])?).into(),
            ))
        }
        6 => {
            ensure!(
                packet.len() >= 40
                    && 40 + usize::from(u16::from_be_bytes(packet[4..6].try_into()?))
                        == packet.len(),
                "IPv6 packet length"
            );
            Ok((
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24])?).into(),
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40])?).into(),
            ))
        }
        _ => anyhow::bail!("unsupported IP version"),
    }
}
