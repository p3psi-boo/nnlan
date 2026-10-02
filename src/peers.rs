//! Neighbor accounting shared by inbound and outbound admission.

use crate::identity::NodeId;
use anyhow::{Result, ensure};
use std::collections::BTreeSet;

pub struct NeighborSet {
    configured: BTreeSet<NodeId>,
    connected: BTreeSet<NodeId>,
    limit: usize,
}

impl NeighborSet {
    pub fn new(limit: usize, configured: impl IntoIterator<Item = NodeId>) -> Result<Self> {
        let configured: BTreeSet<_> = configured.into_iter().collect();
        ensure!(
            limit > 0 && configured.len() <= limit,
            "configured peers exceed neighbor limit"
        );
        Ok(Self {
            configured,
            connected: BTreeSet::new(),
            limit,
        })
    }

    /// Call only after authentication. Discovered nodes do not call this method.
    /// Inbound and outbound paths must use this same accounting object.
    pub fn connect_authenticated(&mut self, node: NodeId) -> Result<()> {
        self.check_capacity(node)?;
        self.connected.insert(node);
        Ok(())
    }

    /// Admission preflight for bounded incoming handshakes; does not trust the key.
    pub fn check_capacity(&self, node: NodeId) -> Result<()> {
        if self.connected.contains(&node) {
            return Ok(());
        }
        let automatic = self.connected.difference(&self.configured).count();
        ensure!(
            self.configured.contains(&node) || automatic < self.limit - self.configured.len(),
            "neighbor capacity reached; retain existing multi-hop routes"
        );
        Ok(())
    }

    pub fn is_configured(&self, node: NodeId) -> bool {
        self.configured.contains(&node)
    }
    pub fn disconnect(&mut self, node: NodeId) {
        self.connected.remove(&node);
    }
    pub fn connected(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.connected.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn reserves_configured_slots_and_counts_both_directions() {
        let mut peers = NeighborSet::new(2, [test_id(1)]).unwrap();
        peers.connect_authenticated(test_id(2)).unwrap();
        assert!(peers.connect_authenticated(test_id(3)).is_err());
        peers.connect_authenticated(test_id(1)).unwrap();
        peers.connect_authenticated(test_id(1)).unwrap();
        assert_eq!(peers.connected().count(), 2);
        peers.disconnect(test_id(2));
        peers.connect_authenticated(test_id(3)).unwrap();
        assert!(NeighborSet::new(1, [test_id(1), test_id(2)]).is_err());
    }
}
