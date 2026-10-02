//! Signed adjacency is also a transitive membership endorsement. No second DHT or
//! membership flooding protocol: one bounded record store drives trust and routing.
use crate::{
    address::{AddressCandidate, candidate},
    config::validate_subnet,
    identity::{Identity, NodeId},
    routing::topology::{RetentionPlan, RoutePath, Topology, edge_key},
};
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_NODES: usize = 4096;
pub const MAX_RECORD: usize = 16_384;
pub const RECORD_TTL: u64 = 60;
// Frozen protocol domain: product renaming must preserve addresses and peer compatibility.
const DOMAIN: &str = "ggbond.node-record.v1";

pub fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub node: NodeId,
    pub boot_id: u64,
    pub name: String,
    pub probe: u32,
    pub relay: bool,
    pub endpoints: Vec<SocketAddr>,
    pub neighbors: Vec<NodeId>,
    /// Sorted indices into `neighbors`, avoiding a second list of 128 public keys.
    pub pinned: Vec<u8>,
    pub subnets: Vec<IpNet>,
    pub serve_exit: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub descriptor: Descriptor,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}
impl Record {
    fn payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.descriptor,
            self.sequence,
            self.issued_at,
            self.expires_at,
        ))?)
    }
    pub fn issue(
        identity: &Identity,
        descriptor: Descriptor,
        sequence: u64,
        now: u64,
    ) -> Result<Self> {
        ensure!(
            descriptor.node == identity.node_id(),
            "record identity mismatch"
        );
        let mut record = Self {
            descriptor,
            sequence,
            issued_at: now,
            expires_at: now.checked_add(RECORD_TTL).context("clock overflow")?,
            signature: vec![],
        };
        record.signature = identity.sign(DOMAIN, &record.payload()?).to_vec();
        record.validate(now)?;
        Ok(record)
    }
    pub fn validate(&self, now: u64) -> Result<()> {
        let d = &self.descriptor;
        ensure!(
            self.expires_at > now
                && self.issued_at <= now.saturating_add(30)
                && self.expires_at.checked_sub(self.issued_at) == Some(RECORD_TTL),
            "record time bounds"
        );
        ensure!(
            !d.name.is_empty() && d.name.len() <= 64 && !d.name.chars().any(char::is_control),
            "record name"
        );
        ensure!(
            d.neighbors.len() <= 128 && d.endpoints.len() <= 16 && d.subnets.len() <= 32,
            "record capacity"
        );
        ensure!(
            d.neighbors.windows(2).all(|w| w[0] < w[1]) && !d.neighbors.contains(&d.node),
            "record neighbors must be sorted and unique"
        );
        ensure!(
            d.pinned.len() <= d.neighbors.len()
                && d.pinned.windows(2).all(|w| w[0] < w[1])
                && d.pinned.iter().all(|&i| usize::from(i) < d.neighbors.len()),
            "record pinned neighbor indices"
        );
        ensure!(
            d.endpoints.windows(2).all(|w| w[0] < w[1])
                && d.endpoints
                    .iter()
                    .all(|e| e.port() > 0 && !e.ip().is_unspecified() && !e.ip().is_multicast()),
            "record endpoints"
        );
        ensure!(
            d.subnets.windows(2).all(|w| w[0] < w[1]),
            "record subnets must be sorted and unique"
        );
        for prefix in &d.subnets {
            validate_subnet(*prefix)?;
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_RECORD,
            "record length"
        );
        d.node.verify(
            DOMAIN,
            &self.payload()?,
            self.signature
                .as_slice()
                .try_into()
                .context("record signature length")?,
        )
    }
    pub fn decode(bytes: &[u8], now: u64) -> Result<Self> {
        ensure!(bytes.len() <= MAX_RECORD, "record length");
        let record: Self = serde_json::from_slice(bytes)?;
        record.validate(now)?;
        Ok(record)
    }
}

pub struct Control {
    local: NodeId,
    records: BTreeMap<NodeId, Record>,
    addresses: BTreeMap<NodeId, AddressCandidate>,
    address_owners: BTreeMap<IpAddr, BTreeSet<NodeId>>,
    direct: BTreeSet<NodeId>,
    trusted: BTreeSet<NodeId>,
    denied: BTreeSet<NodeId>,
    revoked: BTreeSet<NodeId>,
    topology: Topology,
    protected: BTreeSet<(NodeId, NodeId)>,
    retention: Option<RetentionPlan>,
    paths: BTreeMap<NodeId, Option<Vec<NodeId>>>,
    dirty: bool,
}
impl Control {
    pub fn new(local: NodeId) -> Self {
        Self {
            local,
            records: BTreeMap::new(),
            addresses: BTreeMap::new(),
            address_owners: BTreeMap::new(),
            direct: BTreeSet::new(),
            trusted: BTreeSet::new(),
            denied: BTreeSet::new(),
            revoked: BTreeSet::new(),
            topology: Topology::new(MAX_NODES),
            protected: BTreeSet::new(),
            retention: None,
            paths: BTreeMap::new(),
            dirty: true,
        }
    }
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }
    pub fn record(&self, node: NodeId) -> Option<&Record> {
        self.records.get(&node)
    }
    pub fn trusted(&self, node: NodeId) -> bool {
        node == self.local || self.trusted.contains(&node)
    }
    pub fn known_identity(&self, bytes: &[u8; 32]) -> Option<NodeId> {
        if bytes == self.local.as_bytes() {
            Some(self.local)
        } else {
            self.trusted.get(bytes).copied()
        }
    }
    pub fn set_denied(&mut self, denied: BTreeSet<NodeId>) {
        if self.denied != denied {
            self.denied = denied;
            self.dirty = true;
        }
    }
    pub fn take_revoked(&mut self) -> Vec<NodeId> {
        std::mem::take(&mut self.revoked).into_iter().collect()
    }
    pub fn direct(&mut self, peers: impl IntoIterator<Item = NodeId>) {
        let direct: BTreeSet<_> = peers.into_iter().collect();
        if direct != self.direct {
            self.direct = direct;
            self.dirty = true;
        }
    }
    /// `record` must be decoded/validated first; local issuance also validates.
    pub fn insert_verified(&mut self, record: Record) -> Result<bool> {
        let node = record.descriptor.node;
        let address_changed = self
            .records
            .get(&node)
            .is_none_or(|old| old.descriptor.probe != record.descriptor.probe);
        if let Some(old) = self.records.get(&node) {
            if record.sequence <= old.sequence {
                return Ok(false);
            }
            if record.descriptor != old.descriptor {
                self.dirty = true;
            }
        } else {
            ensure!(self.records.len() < MAX_NODES, "node capacity");
            self.dirty = true;
        }
        if address_changed {
            self.remove_addresses(node);
            let address = candidate(node, record.descriptor.probe);
            self.addresses.insert(node, address);
            for ip in [IpAddr::V4(address.ipv4), IpAddr::V6(address.ipv6)] {
                self.address_owners.entry(ip).or_default().insert(node);
            }
        }
        self.records.insert(node, record);
        Ok(true)
    }
    fn remove_addresses(&mut self, node: NodeId) {
        if let Some(address) = self.addresses.remove(&node) {
            for ip in [IpAddr::V4(address.ipv4), IpAddr::V6(address.ipv6)] {
                if let std::collections::btree_map::Entry::Occupied(mut owners) =
                    self.address_owners.entry(ip)
                {
                    owners.get_mut().remove(&node);
                    if owners.get().is_empty() {
                        owners.remove();
                    }
                }
            }
        }
    }
    pub fn refresh(&mut self, now: u64) -> Result<bool> {
        let expired: Vec<_> = self
            .records
            .iter()
            .filter_map(|(&node, record)| (record.expires_at <= now).then_some(node))
            .collect();
        self.dirty |= !expired.is_empty();
        for node in expired {
            self.records.remove(&node);
            self.remove_addresses(node);
        }
        if !self.dirty {
            return Ok(false);
        }
        let previous = std::mem::take(&mut self.trusted);
        self.trusted = self.direct.difference(&self.denied).copied().collect();
        self.trusted.insert(self.local);
        let mut queue: VecDeque<_> = self.trusted.iter().copied().collect();
        while let Some(node) = queue.pop_front() {
            // Only live authenticated adjacency anchors local trust. Our stale
            // signed record must not resurrect a disconnected endorsement cycle.
            if node == self.local {
                continue;
            }
            if let Some(record) = self.records.get(&node) {
                for &endorsed in &record.descriptor.neighbors {
                    if !self.denied.contains(&endorsed)
                        && self.records.contains_key(&endorsed)
                        && self.trusted.insert(endorsed)
                    {
                        queue.push_back(endorsed);
                    }
                }
            }
        }
        self.revoked
            .extend(previous.difference(&self.trusted).copied());
        self.topology = Topology::new(MAX_NODES);
        self.protected.clear();
        for record in self
            .records
            .values()
            .filter(|r| self.trusted.contains(&r.descriptor.node))
        {
            for &index in &record.descriptor.pinned {
                self.protected.insert(edge_key(
                    record.descriptor.node,
                    record.descriptor.neighbors[usize::from(index)],
                ));
            }
        }
        for &node in &self.trusted {
            self.topology.set_node(
                node,
                self.records.get(&node).is_some_and(|r| r.descriptor.relay),
            )?;
        }
        // A verified local UDP connection is stronger evidence than a delayed LSA.
        for &peer in &self.direct {
            if self.trusted.contains(&peer) {
                self.topology.set_link(self.local, peer, 1)?;
            }
        }
        for (&node, record) in &self.records {
            if !self.trusted.contains(&node) {
                continue;
            }
            for &peer in &record.descriptor.neighbors {
                if node >= peer
                    || !self.trusted.contains(&peer)
                    || node == self.local
                    || peer == self.local
                {
                    continue;
                }
                if self
                    .records
                    .get(&peer)
                    .is_some_and(|r| r.descriptor.neighbors.contains(&node))
                {
                    self.topology.set_link(node, peer, 1)?;
                }
            }
        }
        // Most topology updates never lead to an idle-edge retirement. In
        // particular a configured tree needs no pruning plan at all. Invalidate
        // here and build lazily only for an actual unprotected idle candidate.
        self.retention = None;
        self.paths.clear();
        self.dirty = false;
        Ok(true)
    }
    /// Borrow the cached route: forwarding only needs its next hop, not a copy
    /// of every identity on the path for each IP packet. Refresh invalidates it.
    pub fn path(&mut self, target: NodeId) -> Option<&[NodeId]> {
        self.paths
            .entry(target)
            .or_insert_with(|| self.topology.route(self.local, target).map(|p| p.nodes))
            .as_deref()
    }
    pub fn retirement_path(&mut self, peer: NodeId) -> Option<RoutePath> {
        // Missing descriptions are unknown protection policy, never permission
        // to remove a newly admitted neighbor before its first signed record.
        if self.dirty
            || !self.direct.contains(&peer)
            || !self.records.contains_key(&self.local)
            || !self.records.contains_key(&peer)
            || self.protected.contains(&edge_key(self.local, peer))
        {
            return None;
        }
        self.retention
            .get_or_insert_with(|| self.topology.retention_plan(&self.protected))
            .path(self.local, peer)
    }
    pub fn predicted_path(&self, target: NodeId) -> Option<RoutePath> {
        self.topology.route(self.local, target)
    }
    pub fn addresses(&self, node: NodeId) -> Option<AddressCandidate> {
        self.addresses.get(&node).copied()
    }
    pub fn ipv4_owner(&self, ip: std::net::Ipv4Addr) -> Option<NodeId> {
        self.node_for_ip(IpAddr::V4(ip))
    }
    pub fn node_for_ip(&self, ip: IpAddr) -> Option<NodeId> {
        // Keep all colliding claims in public-key order, just as the original
        // record scan did. An index hit never grants membership: consult the
        // current trust set, including between record insertion and refresh.
        self.address_owners
            .get(&ip)?
            .iter()
            .copied()
            .find(|node| self.trusted(*node))
    }
    pub fn resolve(&self, target: &str) -> Result<NodeId> {
        if let Ok(node) = target.parse::<NodeId>() {
            ensure!(self.trusted(node), "target not trusted");
            return Ok(node);
        }
        if let Ok(ip) = target.parse::<IpAddr>() {
            return self.node_for_ip(ip).context("unknown overlay address");
        }
        if target.len() >= 6 && target.chars().all(|c| c.is_ascii_hexdigit()) {
            let lower = target.to_ascii_lowercase();
            let matches: Vec<NodeId> = self
                .records
                .keys()
                .filter(|node| self.trusted(**node) && node.to_string().starts_with(&lower))
                .copied()
                .collect();
            match matches.as_slice() {
                [node] => return Ok(*node),
                [] => (),
                _ => bail!("ambiguous short node id '{target}'; matches multiple nodes"),
            }
        }
        let nodes: Vec<_> = self
            .records
            .values()
            .filter(|r| self.trusted(r.descriptor.node) && r.descriptor.name == target)
            .collect();
        match nodes.as_slice() {
            [record] => Ok(record.descriptor.node),
            [] => bail!("unknown node name"),
            _ => bail!("ambiguous name; use a full public key or overlay IP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn assert_address_index_matches_scan(control: &Control) {
        let expected: BTreeMap<_, _> = control
            .records
            .iter()
            .map(|(&node, r)| (node, candidate(node, r.descriptor.probe)))
            .collect();
        assert_eq!(control.addresses, expected);
        let mut owners: BTreeMap<IpAddr, BTreeSet<NodeId>> = BTreeMap::new();
        for (&node, a) in &expected {
            for ip in [IpAddr::V4(a.ipv4), IpAddr::V6(a.ipv6)] {
                owners.entry(ip).or_default().insert(node);
            }
        }
        assert_eq!(control.address_owners, owners);
        for ip in owners
            .keys()
            .copied()
            .chain(["33.0.0.0".parse().unwrap(), "fd33::".parse().unwrap()])
        {
            let scanned = expected.iter().find_map(|(&node, a)| {
                (control.trusted(node) && (ip == IpAddr::V4(a.ipv4) || ip == IpAddr::V6(a.ipv6)))
                    .then_some(node)
            });
            assert_eq!(control.node_for_ip(ip), scanned);
        }
    }

    #[test]
    fn address_index_preserves_trust_lifecycle_and_immediate_record_updates() {
        let [a, b, c, stranger] = std::array::from_fn::<_, 4, _>(|_| Identity::generate().unwrap());
        let mut control = Control::new(a.node_id());
        for r in [
            record(&a, vec![b.node_id()]),
            record(&b, vec![a.node_id(), c.node_id()]),
            record(&c, vec![b.node_id()]),
            record(&stranger, vec![]),
        ] {
            control.insert_verified(r).unwrap();
            assert_address_index_matches_scan(&control);
        }
        control.direct([b.node_id()]);
        control.refresh(100).unwrap();
        assert!(control.trusted(c.node_id()));
        assert!(!control.trusted(stranger.node_id()));
        assert_address_index_matches_scan(&control);

        let old = control.addresses(b.node_id()).unwrap();
        let mut descriptor = record(&b, vec![a.node_id()]).descriptor;
        descriptor.probe = 1;
        descriptor.boot_id = 2;
        control
            .insert_verified(Record::issue(&b, descriptor.clone(), 2, 120).unwrap())
            .unwrap();
        assert_eq!(control.node_for_ip(old.ipv4.into()), None);
        assert_eq!(control.node_for_ip(old.ipv6.into()), Some(b.node_id()));
        assert_address_index_matches_scan(&control); // Before trust recomputation too.
        control.refresh(120).unwrap();
        assert!(!control.trusted(c.node_id()));
        assert_address_index_matches_scan(&control);

        control.set_denied(BTreeSet::from([b.node_id()]));
        control.refresh(120).unwrap();
        assert_address_index_matches_scan(&control);
        assert_eq!(control.node_for_ip(old.ipv6.into()), None);
        control.set_denied(BTreeSet::new());
        control.direct([]);
        control.refresh(120).unwrap();
        assert_address_index_matches_scan(&control);
        control.direct([b.node_id()]);
        control.refresh(120).unwrap();
        assert_eq!(control.node_for_ip(old.ipv6.into()), Some(b.node_id()));

        // A pure lease renewal keeps both indices and does not dirty topology.
        control
            .insert_verified(Record::issue(&b, descriptor, 3, 130).unwrap())
            .unwrap();
        assert!(!control.refresh(130).unwrap());
        assert_address_index_matches_scan(&control);
        control.refresh(160).unwrap(); // Original records expire; b remains live.
        assert!(control.addresses(c.node_id()).is_none());
        assert_eq!(control.node_for_ip(old.ipv6.into()), Some(b.node_id()));
        assert_address_index_matches_scan(&control);
        control.refresh(190).unwrap();
        assert_address_index_matches_scan(&control);
        assert!(control.addresses.is_empty() && control.address_owners.is_empty());
        control.insert_verified(record(&b, vec![])).unwrap();
        assert_address_index_matches_scan(&control); // Reinsert after full eviction.
    }

    #[test]
    fn address_index_keeps_colliding_claims_and_ignores_replayed_probe_changes() {
        use std::io::Write;
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/ipv4-collision.json")).unwrap();
        let ids: Vec<_> = ["seed_a", "seed_b"]
            .iter()
            .map(|field| {
                let hex = fixture[field].as_str().unwrap();
                let seed: Vec<_> = (0..64)
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect();
                let mut file = tempfile::NamedTempFile::new().unwrap();
                file.write_all(b"GGBKEY1\n").unwrap();
                file.write_all(&seed).unwrap();
                Identity::load(file.path()).unwrap()
            })
            .collect();
        let low = ids.iter().min_by_key(|id| id.node_id()).unwrap();
        let high = ids.iter().max_by_key(|id| id.node_id()).unwrap();
        let ip = candidate(low.node_id(), 0).ipv4;
        assert_eq!(ip, candidate(high.node_id(), 0).ipv4);
        for order in [[low, high], [high, low]] {
            let local = Identity::generate().unwrap().node_id();
            let mut control = Control::new(local);
            for id in order {
                control.insert_verified(record(id, vec![])).unwrap();
            }
            control.direct([low.node_id(), high.node_id()]);
            control.refresh(100).unwrap();
            assert_eq!(control.ipv4_owner(ip), Some(low.node_id()));
            control.set_denied(BTreeSet::from([low.node_id()]));
            control.refresh(100).unwrap();
            assert_eq!(control.ipv4_owner(ip), Some(high.node_id()));
            assert_address_index_matches_scan(&control);
            control.set_denied(BTreeSet::new());
            control.refresh(100).unwrap();
            let mut d = record(low, vec![]).descriptor;
            d.probe = 1;
            control
                .insert_verified(Record::issue(low, d.clone(), 2, 100).unwrap())
                .unwrap();
            assert_eq!(control.ipv4_owner(ip), Some(high.node_id()));
            assert_address_index_matches_scan(&control);
            assert!(!control.insert_verified(record(low, vec![])).unwrap());
            assert_eq!(control.ipv4_owner(ip), Some(high.node_id()));
            d.probe = 0;
            control
                .insert_verified(Record::issue(low, d, 3, 110).unwrap())
                .unwrap();
            assert_eq!(control.ipv4_owner(ip), Some(low.node_id()));
            control.refresh(160).unwrap(); // Higher key expires; lower claim remains.
            assert_eq!(control.ipv4_owner(ip), Some(low.node_id()));
            assert_address_index_matches_scan(&control);
            control.refresh(170).unwrap();
            assert_address_index_matches_scan(&control);
            assert!(control.address_owners.is_empty());
        }
    }

    fn record(id: &Identity, neighbors: Vec<NodeId>) -> Record {
        let mut neighbors = neighbors;
        neighbors.sort();
        Record::issue(
            id,
            Descriptor {
                node: id.node_id(),
                boot_id: 1,
                name: "test".into(),
                probe: 0,
                relay: true,
                endpoints: vec![],
                neighbors,
                pinned: vec![],
                subnets: vec![],
                serve_exit: false,
            },
            1,
            100,
        )
        .unwrap()
    }
    #[test]
    fn transitive_signed_adjacency_requires_mutual_links_and_live_anchor() {
        let [a, c, d, b] = std::array::from_fn::<_, 4, _>(|_| Identity::generate().unwrap());
        let mut control = Control::new(a.node_id());
        assert_eq!(
            control.known_identity(a.node_id().as_bytes()),
            Some(a.node_id())
        );
        assert_eq!(control.known_identity(b.node_id().as_bytes()), None);
        assert_eq!(control.known_identity(&[0; 32]), None);
        control.direct([c.node_id()]);
        for r in [
            record(&a, vec![c.node_id()]),
            record(&c, vec![a.node_id(), d.node_id()]),
            record(&d, vec![c.node_id(), b.node_id()]),
            record(&b, vec![d.node_id()]),
        ] {
            control.insert_verified(r).unwrap();
        }
        control.refresh(100).unwrap();
        assert!(control.trusted(b.node_id()));
        assert_eq!(
            control.known_identity(b.node_id().as_bytes()),
            Some(b.node_id())
        );
        assert_eq!(
            control.path(b.node_id()).unwrap(),
            vec![a.node_id(), c.node_id(), d.node_id(), b.node_id()]
        );
        control.direct([]);
        control.refresh(100).unwrap();
        assert!(control.path(b.node_id()).is_none());
        assert_eq!(control.known_identity(b.node_id().as_bytes()), None);
        assert!(
            !control.trusted(b.node_id()),
            "stale local LSA must not anchor a cycle"
        );
        control.refresh(160).unwrap();
        assert!(!control.trusted(b.node_id()));
    }
    #[test]
    fn signatures_versions_time_and_bounds_are_checked() {
        let id = Identity::generate().unwrap();
        let mut r = record(&id, vec![]);
        assert!(r.validate(160).is_err());
        r.descriptor.name = "forged".into();
        assert!(r.validate(100).is_err());
        let mut c = Control::new(id.node_id());
        let r = record(&id, vec![]);
        assert!(c.insert_verified(r.clone()).unwrap());
        assert!(!c.insert_verified(r).unwrap());
        assert!(Record::decode(&vec![0; MAX_RECORD + 1], 100).is_err());
    }

    #[test]
    fn withdrawal_alternate_endorsement_and_local_denial_override_live_anchors() {
        let [a, c, d, b] = std::array::from_fn::<_, 4, _>(|_| Identity::generate().unwrap());
        let mut control = Control::new(a.node_id());
        control.direct([c.node_id(), d.node_id()]);
        for r in [
            record(&a, vec![c.node_id(), d.node_id()]),
            record(&c, vec![a.node_id(), b.node_id()]),
            record(&d, vec![a.node_id(), b.node_id()]),
            record(&b, vec![c.node_id(), d.node_id()]),
        ] {
            control.insert_verified(r).unwrap();
        }
        control.refresh(100).unwrap();
        assert!(control.trusted(b.node_id()));
        let old = control.record(c.node_id()).unwrap().clone();
        let withdrawn =
            Record::issue(&c, record(&c, vec![a.node_id()]).descriptor, 2, 100).unwrap();
        control.insert_verified(withdrawn).unwrap();
        assert!(!control.insert_verified(old).unwrap());
        control.refresh(100).unwrap();
        assert_eq!(
            control.path(b.node_id()).unwrap(),
            [a.node_id(), d.node_id(), b.node_id()]
        );
        assert!(control.take_revoked().is_empty());
        control.set_denied([d.node_id()].into());
        control.refresh(100).unwrap();
        assert!(!control.trusted(d.node_id()));
        assert!(!control.trusted(b.node_id()));
        assert!(control.path(b.node_id()).is_none());
        let revoked = control.take_revoked();
        assert!(revoked.contains(&b.node_id()) && revoked.contains(&d.node_id()));
        control.set_denied([b.node_id()].into());
        control.refresh(100).unwrap();
        assert!(control.trusted(d.node_id()));
        assert!(
            !control.trusted(b.node_id()),
            "another issuer cannot override local denial"
        );
        control.set_denied(BTreeSet::new());
        control.refresh(100).unwrap();
        assert!(control.trusted(b.node_id()));
        control.direct([]);
        control.refresh(100).unwrap();
        assert!(
            !control.trusted(c.node_id())
                && !control.trusted(d.node_id())
                && !control.trusted(b.node_id())
        );
    }

    #[test]
    fn resolve_supports_pubkey_ip_name_and_short_id() {
        let [a, b] = std::array::from_fn::<_, 2, _>(|_| Identity::generate().unwrap());
        let mut control = Control::new(a.node_id());
        let mut desc_b = record(&b, vec![a.node_id()]).descriptor;
        desc_b.name = "node-beta".into();
        let rec_b = Record::issue(&b, desc_b, 1, 100).unwrap();
        let rec_a = record(&a, vec![b.node_id()]);
        control.insert_verified(rec_a).unwrap();
        control.insert_verified(rec_b).unwrap();
        control.direct([b.node_id()]);
        control.refresh(100).unwrap();

        let b_id = b.node_id();
        let b_str = b_id.to_string();
        let b_short = &b_str[..8];
        let b_addr = control.addresses(b_id).unwrap();

        // Exact NodeId
        assert_eq!(control.resolve(&b_str).unwrap(), b_id);
        // Short NodeId prefix
        assert_eq!(control.resolve(b_short).unwrap(), b_id);
        // Case-insensitive short prefix
        assert_eq!(control.resolve(&b_short.to_uppercase()).unwrap(), b_id);
        // Node name
        assert_eq!(control.resolve("node-beta").unwrap(), b_id);
        // Overlay IPv4
        assert_eq!(control.resolve(&b_addr.ipv4.to_string()).unwrap(), b_id);
        // Overlay IPv6
        assert_eq!(control.resolve(&b_addr.ipv6.to_string()).unwrap(), b_id);

        // Unknown
        assert!(control.resolve("node-unknown").is_err());
        assert!(control.resolve("123456").is_err());
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    #[test]
    fn signed_pin_indices_are_bounded_and_remote_pins_protect_inbound_edges() {
        let ids: Vec<_> = (0..3).map(|_| Identity::generate().unwrap()).collect();
        let mut control = Control::new(ids[0].node_id());
        control.direct([ids[1].node_id(), ids[2].node_id()]);
        for (i, id) in ids.iter().enumerate() {
            let mut neighbors: Vec<_> = ids
                .iter()
                .filter(|other| other.node_id() != id.node_id())
                .map(Identity::node_id)
                .collect();
            neighbors.sort();
            // All three edges are configured from their remote end as needed.
            let pinned = if i == 0 { vec![] } else { vec![0, 1] };
            let descriptor = Descriptor {
                node: id.node_id(),
                boot_id: 1,
                name: "test".into(),
                probe: 0,
                relay: true,
                endpoints: vec![],
                neighbors,
                pinned,
                subnets: vec![],
                serve_exit: false,
            };
            let record = Record::issue(id, descriptor.clone(), 1, 100).unwrap();
            control.insert_verified(record).unwrap();
            for bad in [vec![2], vec![0, 0], vec![1, 0], vec![255]] {
                let mut malformed = descriptor.clone();
                malformed.pinned = bad;
                assert!(Record::issue(id, malformed, 2, 100).is_err());
            }
        }
        control.refresh(100).unwrap();
        assert!(control.retention.is_none());
        assert!(control.retirement_path(ids[1].node_id()).is_none());
        assert!(control.retirement_path(ids[2].node_id()).is_none());
        assert!(control.retention.is_none()); // Protected edges need no global plan.
        // Release the target edge, leaving a protected two-hop backup.
        let mut record = control.record(ids[1].node_id()).unwrap().clone();
        let position = record
            .descriptor
            .neighbors
            .iter()
            .position(|n| *n == ids[0].node_id())
            .unwrap();
        record
            .descriptor
            .pinned
            .retain(|&i| usize::from(i) != position);
        let record = Record::issue(&ids[1], record.descriptor, 2, 100).unwrap();
        control.insert_verified(record).unwrap();
        // Dirty/missing descriptions must not make pruning decisions.
        assert!(control.retirement_path(ids[1].node_id()).is_none());
        control.refresh(100).unwrap();
        assert!(control.retention.is_none());
        assert_eq!(
            control.retirement_path(ids[1].node_id()).unwrap().nodes,
            [ids[0].node_id(), ids[2].node_id(), ids[1].node_id()]
        );
        assert!(control.retention.is_some());
        control.direct([ids[1].node_id()]);
        control.refresh(100).unwrap();
        assert!(control.retention.is_none()); // Changed adjacency invalidates it.
        assert!(control.retirement_path(ids[1].node_id()).is_none());
    }
}
