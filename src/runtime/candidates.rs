//! Bounded candidate provenance. A neighbor refresh replaces its previous NAT
//! observation; interface snapshots replace host addresses, never append forever.
use crate::{config::Config, identity::NodeId};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

pub(super) const LIMIT: usize = 16;
const MAX_OBSERVERS: usize = 128;
const TTL: Duration = Duration::from_secs(30);

pub(super) fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => SocketAddr::new(
            v6.ip().to_ipv4_mapped().expect("mapped IPv4").into(),
            v6.port(),
        ),
        _ => address,
    }
}
pub(super) fn usable(address: SocketAddr, listen: SocketAddr) -> bool {
    if address.port() == 0 || (!listen.is_ipv6() && address.is_ipv6()) {
        return false;
    }
    let ip = address.ip();
    if ip.is_unspecified() || ip.is_multicast() || (ip.is_loopback() && !listen.ip().is_loopback())
    {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_link_local() && ip.octets()[0] != 33 && ip != std::net::Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.segments()[0] != 0xfd33,
    }
}

pub(super) struct Candidates {
    fixed: BTreeSet<SocketAddr>,
    local: BTreeSet<SocketAddr>,
    local_at: Instant,
    observations: BTreeMap<NodeId, (SocketAddr, Instant)>,
    advertised: BTreeSet<SocketAddr>,
    listen: SocketAddr,
}
impl Candidates {
    pub fn new(config: &Config, local: BTreeSet<SocketAddr>, now: Instant) -> Self {
        let mut value = Self {
            fixed: config.endpoints.iter().copied().map(canonical).collect(),
            local: BTreeSet::new(),
            local_at: now,
            observations: BTreeMap::new(),
            advertised: BTreeSet::new(),
            listen: config.listen,
        };
        value.update_local(local, now);
        value
    }
    pub fn advertised(&self) -> &BTreeSet<SocketAddr> {
        &self.advertised
    }
    /// Only host/configuration evidence may suppress a self-dial. A neighbor's
    /// observation is a hint, not proof that its claimed endpoint belongs to us.
    pub fn is_local_endpoint(&self, endpoint: &SocketAddr) -> bool {
        let endpoint = canonical(*endpoint);
        self.fixed.contains(&endpoint) || self.local.contains(&endpoint)
    }
    pub fn update_local(&mut self, local: BTreeSet<SocketAddr>, now: Instant) -> bool {
        self.local = local
            .into_iter()
            .map(canonical)
            .filter(|a| usable(*a, self.listen))
            .take(LIMIT)
            .collect();
        self.local_at = now;
        self.rebuild()
    }
    pub fn observe(&mut self, peer: NodeId, address: SocketAddr, now: Instant) -> bool {
        let address = canonical(address);
        if !usable(address, self.listen)
            || (self.observations.len() >= MAX_OBSERVERS && !self.observations.contains_key(&peer))
        {
            return false;
        }
        let previous = self.observations.insert(peer, (address, now));
        // Heartbeats refresh lifetime without reshuffling or re-signing the same
        // advertised set once per neighbor per second.
        if previous.is_some_and(|(old, _)| old == address) {
            return false;
        }
        self.rebuild()
    }
    pub fn disconnected(&mut self, peer: NodeId) -> bool {
        if self.observations.remove(&peer).is_some() {
            self.rebuild()
        } else {
            false
        }
    }
    pub fn expire(&mut self, now: Instant) -> bool {
        let count = self.observations.len();
        self.observations
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < TTL);
        let local_expired =
            !self.local.is_empty() && now.saturating_duration_since(self.local_at) >= TTL;
        if local_expired {
            self.local.clear();
        }
        (count != self.observations.len() || local_expired) && self.rebuild()
    }
    fn rebuild(&mut self) -> bool {
        let mut selected = self.fixed.clone();
        let mut observations: Vec<_> = self
            .observations
            .iter()
            .map(|(&peer, &(address, at))| (at, peer, address))
            .collect();
        observations.sort_unstable_by(|a, b| b.cmp(a));
        let mut observed = observations.into_iter().map(|(_, _, address)| address);
        let mut local = self.local.iter().copied();
        // Keep both host and observed candidates when many interfaces/neighbors
        // compete. Explicit operator endpoints always have priority.
        while selected.len() < LIMIT {
            let a = observed.next();
            let b = local.next();
            if a.is_none() && b.is_none() {
                break;
            }
            for address in [a, b].into_iter().flatten() {
                if selected.len() < LIMIT {
                    selected.insert(address);
                }
            }
        }
        if selected == self.advertised {
            return false;
        }
        self.advertised = selected;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;
    fn address(port: u16) -> SocketAddr {
        SocketAddr::from(([198, 18, 0, 1], port))
    }
    #[test]
    fn repeated_nat_rebinding_replaces_instead_of_filling_the_limit() {
        let now = Instant::now();
        let mut c = Candidates::new(&Config::default(), BTreeSet::new(), now);
        for port in 40000..40040 {
            assert!(c.observe(test_id(1), address(port), now));
            assert_eq!(c.advertised(), &BTreeSet::from([address(port)]));
        }
        assert_eq!(c.observations.len(), 1);
        assert!(!c.observe(test_id(1), address(40039), now + TTL / 2));
        assert!(!c.expire(now + TTL));
        assert!(c.expire(now + TTL + TTL / 2));
        assert!(c.advertised().is_empty());
    }
    #[test]
    fn observations_are_reference_counted_by_authenticated_neighbor() {
        let now = Instant::now();
        let mut c = Candidates::new(&Config::default(), BTreeSet::new(), now);
        assert!(c.observe(test_id(1), address(1), now));
        assert!(!c.observe(test_id(2), address(1), now));
        assert!(!c.disconnected(test_id(1)));
        assert!(c.advertised().contains(&address(1)));
        assert!(!c.is_local_endpoint(&address(1)));
        assert!(c.disconnected(test_id(2)));
        assert!(c.advertised().is_empty());
    }
    #[test]
    fn local_snapshots_and_ttl_preserve_explicit_operator_endpoints() {
        let now = Instant::now();
        let config = Config {
            endpoints: vec![address(1)],
            ..Config::default()
        };
        let mut c = Candidates::new(&config, BTreeSet::from([address(1), address(2)]), now);
        assert!(c.update_local(BTreeSet::from([address(3)]), now));
        assert!(!c.is_local_endpoint(&address(2)));
        assert!(c.is_local_endpoint(&address(1)));
        assert!(c.is_local_endpoint(&address(3)));
        assert_eq!(c.advertised(), &BTreeSet::from([address(1), address(3)]));
        assert!(c.expire(now + TTL));
        assert_eq!(c.advertised(), &BTreeSet::from([address(1)]));
        assert!(c.update_local(BTreeSet::from([address(3)]), now + TTL));
    }
    #[test]
    fn sources_share_the_bound_without_starving_observed_addresses() {
        let now = Instant::now();
        let mut c = Candidates::new(&Config::default(), (1..=16).map(address).collect(), now);
        for peer in 0..128 {
            c.observe(test_id(peer), address(1000 + u16::from(peer)), now);
        }
        assert_eq!(c.observations.len(), MAX_OBSERVERS);
        assert_eq!(c.advertised().len(), LIMIT);
        assert_eq!(c.advertised().iter().filter(|a| a.port() < 1000).count(), 8);
        assert!(!c.observe(test_id(128), address(9999), now));
        assert!(c.observe(test_id(127), address(9998), now + Duration::from_secs(1)));
        assert!(c.advertised().contains(&address(9998)));
        for bad in [
            "0.0.0.0:7331",
            "127.0.0.1:7331",
            "224.0.0.1:7331",
            "255.255.255.255:7331",
            "33.1.2.3:7331",
            "[fd33::1]:7331",
            "[::ffff:33.1.2.3]:7331",
        ] {
            assert!(!c.observe(test_id(127), bad.parse().unwrap(), now));
        }
        assert!(c.advertised().contains(&address(9998)));
    }
}
