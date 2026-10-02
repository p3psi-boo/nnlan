use crate::identity::NodeId;
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    net::{Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub name: String,
    pub identity_file: PathBuf,
    pub listen: SocketAddr,
    pub relay: bool,
    pub max_neighbors: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
    pub tun: TunConfig,
    pub routes: RouteConfig,
    pub endpoints: Vec<SocketAddr>,
    pub bandwidth_mbps: u32,
    pub repair: RepairConfig,
    pub dns_servers: Vec<SocketAddr>,
    /// UID of the OS DHCP client. Only its DHCP port pairs may use the underlay.
    pub dhcp_client_uid: Option<u32>,
    /// Local policy only; overrides direct admission and transitive endorsements.
    pub denied: BTreeSet<NodeId>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            name: "nnlan".into(),
            identity_file: "identity.key".into(),
            listen: "0.0.0.0:7331".parse().expect("literal socket address"),
            relay: true,
            max_neighbors: 16,
            peers: vec![],
            tun: TunConfig::default(),
            routes: RouteConfig::default(),
            endpoints: vec![],
            bandwidth_mbps: 1000,
            repair: RepairConfig::default(),
            dns_servers: vec![],
            dhcp_client_uid: None,
            denied: BTreeSet::new(),
        }
    }
}

/// Local outgoing protection policy. Receiving/ACK support is always enabled,
/// so peers may choose different policies without another negotiation protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RepairConfig {
    pub fec: bool,
    pub rtx: bool,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            fec: true,
            rtx: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub endpoint: String,
    pub public_key: NodeId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
    pub enabled: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "nnlan0".into(),
            mtu: 1280,
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    pub advertise: Vec<IpNet>,
    pub accept: Vec<AcceptedRoute>,
    pub exit_node: Option<NodeId>,
    pub serve_exit: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRoute {
    pub prefix: IpNet,
    pub via: NodeId,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
        let config: Self = toml::from_str(&text).context("parse configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Relative paths are relative to the config file, never the current directory.
    pub fn identity_path(&self, config_path: &Path) -> PathBuf {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&self.identity_file)
    }

    pub fn adjacent_path(&self, config_path: &Path, name: &str) -> PathBuf {
        config_path.parent().unwrap_or(Path::new(".")).join(name)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        self.validate()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        if let Ok(meta) = fs::symlink_metadata(path) {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "config path must be a regular file"
            );
            // A root daemon editing a user's config must not take ownership of it.
            std::os::unix::fs::chown(file.path(), Some(meta.uid()), Some(meta.gid()))?;
        }
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| e.error)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.denied.len() <= 4096, "local deny capacity reached");
        ensure!(
            self.dhcp_client_uid != Some(u32::MAX),
            "invalid DHCP client UID"
        );
        ensure!(
            self.dns_servers.len() <= 8
                && self
                    .dns_servers
                    .iter()
                    .all(|s| s.port() != 0 && !s.ip().is_unspecified() && !s.ip().is_multicast()),
            "dns_servers must contain at most eight unicast IP:port addresses"
        );
        ensure!(
            (1..=100_000).contains(&self.bandwidth_mbps),
            "bandwidth_mbps must be in 1..=100000"
        );
        ensure!(
            self.endpoints.len() <= 16
                && self
                    .endpoints
                    .iter()
                    .all(|e| e.port() != 0 && !e.ip().is_unspecified() && !e.ip().is_multicast()),
            "invalid advertised endpoints"
        );
        ensure!(
            self.routes.advertise.len() <= 32 && self.routes.accept.len() <= 128,
            "route configuration capacity exceeded"
        );
        ensure!(
            self.schema_version == 1,
            "unsupported configuration schema_version"
        );
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 64
                && !self.name.chars().any(char::is_control),
            "name must contain 1..64 bytes"
        );
        ensure!(
            !self.identity_file.as_os_str().is_empty(),
            "identity_file must be set"
        );
        ensure!(self.listen.port() != 0, "listen port must be nonzero");
        ensure!(
            (1..=128).contains(&self.max_neighbors),
            "max_neighbors must be in 1..=128"
        );
        ensure!(
            self.peers.len() <= self.max_neighbors,
            "configured peers exceed max_neighbors"
        );
        let mut keys = BTreeSet::new();
        for peer in &self.peers {
            validate_endpoint(&peer.endpoint)?;
            ensure!(
                keys.insert(peer.public_key),
                "duplicate configured peer {}",
                peer.public_key
            );
        }
        ensure!(
            !self.tun.name.is_empty()
                && self.tun.name.len() < 16
                && self
                    .tun
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid TUN name"
        );
        ensure!(
            (1280..=9000).contains(&self.tun.mtu),
            "TUN MTU must be in 1280..=9000; actual path MTU is negotiated later"
        );
        let mut prefixes = BTreeSet::new();
        for route in &self.routes.accept {
            validate_subnet(route.prefix)?;
            ensure!(
                prefixes.insert(route.prefix),
                "at most one accepted publisher per prefix: {}",
                route.prefix
            );
        }
        prefixes.clear();
        for prefix in &self.routes.advertise {
            validate_subnet(*prefix)?;
            ensure!(
                prefixes.insert(*prefix),
                "duplicate advertised prefix: {prefix}"
            );
        }
        Ok(())
    }
}

pub fn validate_subnet(prefix: IpNet) -> Result<()> {
    ensure!(
        prefix == prefix.trunc(),
        "prefix must be canonical: use {}",
        prefix.trunc()
    );
    ensure!(
        prefix.prefix_len() != 0,
        "default routes belong to explicit Exit Node selection"
    );
    let pool: IpNet = if prefix.addr().is_ipv4() {
        "33.0.0.0/8"
    } else {
        "fd33::/16"
    }
    .parse()?;
    ensure!(
        !pool.contains(&prefix.addr()) && !prefix.contains(&pool.addr()),
        "subnet overlaps the node address pool"
    );
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        ensure!(
            address.port() != 0
                && !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && address.ip() != std::net::Ipv4Addr::BROADCAST,
            "peer endpoint must be unicast with a nonzero port"
        );
        return Ok(());
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .context("peer endpoint must be host:port or [IPv6]:port")?;
    ensure!(
        port.parse::<u16>().is_ok_and(|p| p != 0),
        "invalid peer port"
    );
    ensure!(
        host.parse::<Ipv6Addr>().is_err() && !host.contains(':'),
        "IPv6 endpoints require brackets"
    );
    ensure!(
        host.len() <= 253
            && host.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid peer hostname"
    );
    ensure!(
        !host.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "invalid IPv4 endpoint"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn defaults_and_roundtrip() {
        let config = Config::default();
        assert!(config.relay);
        assert_eq!(config.max_neighbors, 16);
        assert_eq!(
            config.repair,
            RepairConfig {
                fec: true,
                rtx: true
            }
        );
        config.validate().unwrap();
        let text = toml::to_string_pretty(&config).unwrap();
        toml::from_str::<Config>(&text).unwrap().validate().unwrap();
        assert!(toml::from_str::<Config>("relai = true").is_err());
    }

    #[test]
    fn repair_switches_are_independent_default_on_and_strict() {
        for fec in [false, true] {
            for rtx in [false, true] {
                let text = format!("[repair]\nfec = {fec}\nrtx = {rtx}\n");
                let c: Config = toml::from_str(&text).unwrap();
                assert_eq!(c.repair, RepairConfig { fec, rtx });
                let encoded = toml::to_string_pretty(&c).unwrap();
                assert_eq!(toml::from_str::<Config>(&encoded).unwrap().repair, c.repair);
            }
        }
        let c: Config = toml::from_str("[repair]\nfec = false").unwrap();
        assert_eq!(
            c.repair,
            RepairConfig {
                fec: false,
                rtx: true
            }
        );
        assert!(toml::from_str::<Config>("[repair]\nretry = false").is_err());
        assert!(toml::from_str::<Config>("[repair]\nfec = 0").is_err());
    }

    #[test]
    fn save_preserves_owner_and_rejects_symlink_replacement() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut config = Config::default();
        config.save(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        config.name = "changed".into();
        config.save(&path).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert_eq!(after.mode() & 0o777, 0o600);
        assert_eq!(Config::load(&path).unwrap().name, "changed");
        let link = directory.path().join("symlink.toml");
        symlink(&path, &link).unwrap();
        assert!(config.save(&link).is_err());
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    }

    #[test]
    fn peer_requires_key_and_valid_endpoint() {
        assert!(toml::from_str::<Config>("[[peers]]\nendpoint = 'localhost:7331'").is_err());
        for endpoint in [
            "host:0",
            "0.0.0.0:12",
            "[::]:12",
            "host",
            "udp://host:12",
            "::1:12",
            "bad host:12",
            "999.1.1.1:12",
            "255.255.255.255:12",
        ] {
            assert!(validate_endpoint(endpoint).is_err(), "{endpoint}");
        }
        for endpoint in ["localhost:7331", "peer.example:1", "127.0.0.1:2", "[::1]:3"] {
            validate_endpoint(endpoint).unwrap();
        }
    }

    #[test]
    fn route_and_neighbor_constraints() {
        let mut c = Config {
            max_neighbors: 1,
            ..Config::default()
        };
        c.peers = vec![
            PeerConfig {
                endpoint: "localhost:1".into(),
                public_key: test_id(1)
            };
            2
        ];
        assert!(c.validate().is_err());
        c.peers.clear();
        c.routes.accept = vec![
            AcceptedRoute {
                prefix: "192.168.1.0/24".parse().unwrap(),
                via: test_id(1),
            },
            AcceptedRoute {
                prefix: "192.168.1.0/24".parse().unwrap(),
                via: test_id(2),
            },
        ];
        assert!(c.validate().is_err());
        for prefix in ["192.168.1.1/24", "0.0.0.0/0", "33.1.0.0/16", "fd33::/32"] {
            assert!(validate_subnet(prefix.parse().unwrap()).is_err());
        }
    }
}
