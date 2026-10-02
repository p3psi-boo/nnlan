//! Signed introductions and transitive reachability. No account or approval server.
//! Direct anchors must be inserted only after a real handshake confirms identity.

use crate::identity::{Identity, NodeId};
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// Frozen protocol domain: product renaming must preserve addresses and peer compatibility.
const DOMAIN: &str = "ggbond.introduction.v1";

#[derive(Clone, Debug)]
pub struct Introduction {
    pub issuer: NodeId,
    pub subject: NodeId,
    pub sequence: u64,
    pub expires_at: u64,
    signature: [u8; 64],
}

impl Introduction {
    pub fn issue(identity: &Identity, subject: NodeId, sequence: u64, expires_at: u64) -> Self {
        let mut record = Self {
            issuer: identity.node_id(),
            subject,
            sequence,
            expires_at,
            signature: [0; 64],
        };
        record.signature = identity.sign(DOMAIN, &record.payload());
        record
    }

    fn payload(&self) -> [u8; 80] {
        let mut out = [0; 80];
        out[..32].copy_from_slice(self.issuer.as_bytes());
        out[32..64].copy_from_slice(self.subject.as_bytes());
        out[64..72].copy_from_slice(&self.sequence.to_be_bytes());
        out[72..].copy_from_slice(&self.expires_at.to_be_bytes());
        out
    }
}

pub struct TrustGraph {
    anchors: BTreeSet<NodeId>,
    denied: BTreeSet<NodeId>,
    records: BTreeMap<(NodeId, NodeId), Introduction>,
    capacity: usize,
}

impl TrustGraph {
    pub fn new(capacity: usize) -> Self {
        Self {
            anchors: BTreeSet::new(),
            denied: BTreeSet::new(),
            records: BTreeMap::new(),
            capacity,
        }
    }

    pub fn add_verified_anchor(&mut self, node: NodeId) -> Result<()> {
        ensure!(
            self.anchors.contains(&node) || self.anchors.len() < self.capacity,
            "trust anchor capacity reached"
        );
        self.anchors.insert(node);
        Ok(())
    }

    pub fn remove_anchor(&mut self, node: NodeId) {
        self.anchors.remove(&node);
    }

    pub fn deny_locally(&mut self, node: NodeId) -> Result<()> {
        ensure!(
            self.denied.contains(&node) || self.denied.len() < self.capacity,
            "local deny capacity reached"
        );
        self.denied.insert(node);
        Ok(())
    }

    /// now/expires_at are Unix seconds. Keep sequence high-water marks even after
    /// expiry; eviction and durable revocation are intentionally not implemented yet.
    pub fn insert(&mut self, record: Introduction, now: u64) -> Result<bool> {
        ensure!(
            record.issuer != record.subject,
            "self-introduction adds no trust"
        );
        ensure!(record.expires_at > now, "introduction expired");
        record
            .issuer
            .verify(DOMAIN, &record.payload(), &record.signature)?;
        let key = (record.issuer, record.subject);
        if let Some(old) = self.records.get(&key) {
            if record.sequence <= old.sequence {
                return Ok(false);
            }
        } else {
            ensure!(
                self.records.len() < self.capacity,
                "introduction capacity reached"
            );
        }
        self.records.insert(key, record);
        Ok(true)
    }

    pub fn trusted_at(&self, now: u64) -> BTreeSet<NodeId> {
        let mut result: BTreeSet<_> = self.anchors.difference(&self.denied).copied().collect();
        let mut queue: VecDeque<_> = result.iter().copied().collect();
        let mut outgoing: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
        for record in self.records.values().filter(|r| r.expires_at > now) {
            outgoing
                .entry(record.issuer)
                .or_default()
                .push(record.subject);
        }
        while let Some(node) = queue.pop_front() {
            if let Some(subjects) = outgoing.get(&node) {
                for &subject in subjects {
                    if !self.denied.contains(&subject) && result.insert(subject) {
                        queue.push_back(subject);
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_expiry_transitivity_and_explicit_denial() {
        let [c, d, b] = std::array::from_fn::<_, 3, _>(|_| Identity::generate().unwrap());
        let mut graph = TrustGraph::new(8);
        graph.add_verified_anchor(c.node_id()).unwrap();
        let cd = Introduction::issue(&c, d.node_id(), 1, 100);
        graph.insert(cd.clone(), 0).unwrap();
        graph
            .insert(Introduction::issue(&d, b.node_id(), 1, 100), 0)
            .unwrap();
        assert!(graph.trusted_at(1).contains(&b.node_id()));
        assert!(!graph.trusted_at(100).contains(&b.node_id()));
        assert!(!graph.insert(cd.clone(), 0).unwrap());
        let mut forged = cd;
        forged.sequence = 99;
        assert!(graph.insert(forged, 0).is_err());
        graph.deny_locally(d.node_id()).unwrap();
        assert!(!graph.trusted_at(1).contains(&b.node_id()));
        graph
            .insert(Introduction::issue(&c, b.node_id(), 1, 100), 0)
            .unwrap();
        assert!(graph.trusted_at(1).contains(&b.node_id()));
        graph.deny_locally(b.node_id()).unwrap();
        assert!(!graph.trusted_at(1).contains(&b.node_id()));
    }

    #[test]
    fn disconnected_cycle_does_not_create_membership() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut graph = TrustGraph::new(2);
        graph
            .insert(Introduction::issue(&a, b.node_id(), 1, 100), 1)
            .unwrap();
        graph
            .insert(Introduction::issue(&b, a.node_id(), 1, 100), 1)
            .unwrap();
        assert!(graph.trusted_at(1).is_empty());
        graph.add_verified_anchor(a.node_id()).unwrap();
        assert_eq!(graph.trusted_at(1).len(), 2);
        graph.remove_anchor(a.node_id());
        assert!(graph.trusted_at(1).is_empty());
    }
}
