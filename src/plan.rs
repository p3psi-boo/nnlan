//! Inspection without socket binding, TUN creation or kernel route changes.
use crate::{
    address::{AddressCandidate, IPV4_POOL, IPV6_POOL, candidate},
    config::{Config, PeerConfig, RouteConfig, TunConfig},
    identity::{Identity, NodeId},
    routing::exit::ExitPolicy,
};
use anyhow::{Result, ensure};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Plan {
    pub stage: &'static str,
    pub node_id: NodeId,
    pub ipv4_pool: &'static str,
    pub ipv6_pool: &'static str,
    pub address_candidate: AddressCandidate,
    pub addresses_claimed: bool,
    pub listen: std::net::SocketAddr,
    pub relay_enabled: bool,
    pub max_neighbors: usize,
    pub automatic_neighbor_slots: usize,
    pub peers: Vec<PeerConfig>,
    pub denied: std::collections::BTreeSet<NodeId>,
    pub tun: TunConfig,
    pub repair: crate::config::RepairConfig,
    pub routes: RouteConfig,
    pub desired_exit_policy: ExitPolicy,
    pub network_running: bool,
    pub kernel_exit_guard_installed: bool,
    pub pending: &'static [&'static str],
}

impl Plan {
    pub fn build(config: &Config, identity: &Identity) -> Result<Self> {
        config.validate()?;
        let node_id = identity.node_id();
        ensure!(
            !config.denied.contains(&node_id),
            "cannot deny local identity"
        );
        ensure!(
            config.peers.iter().all(|peer| peer.public_key != node_id),
            "a node cannot configure itself as a peer"
        );
        ensure!(
            config.routes.exit_node != Some(node_id),
            "a node cannot select itself as its Exit Node"
        );
        ensure!(
            config
                .routes
                .accept
                .iter()
                .all(|route| route.via != node_id),
            "a node cannot accept its own subnet advertisement"
        );
        ensure!(
            !config.routes.serve_exit || config.routes.exit_node.is_none(),
            "serve_exit and selecting an exit are mutually exclusive node roles"
        );
        let mut desired_exit_policy = ExitPolicy::default();
        if let Some(node) = config.routes.exit_node {
            desired_exit_policy.select(node);
        }
        Ok(Self {
            stage: "linux-development",
            node_id,
            ipv4_pool: IPV4_POOL,
            ipv6_pool: IPV6_POOL,
            address_candidate: candidate(node_id, 0),
            addresses_claimed: false,
            listen: config.listen,
            relay_enabled: config.relay,
            max_neighbors: config.max_neighbors,
            automatic_neighbor_slots: config.max_neighbors - config.peers.len(),
            peers: config.peers.clone(),
            denied: config.denied.clone(),
            tun: config.tun.clone(),
            repair: config.repair,
            routes: config.routes.clone(),
            desired_exit_policy,
            network_running: false,
            kernel_exit_guard_installed: false,
            pending: &[
                "exit boot ordering and dynamic underlay address renewal acceptance",
                "NAT topology matrix and large real-network scale acceptance",
                "extended policy ownership, DNS boundary and restart stress tests",
                "full weak-network comparisons, PMTU and throughput/latency benchmarks",
            ],
        })
    }
}
