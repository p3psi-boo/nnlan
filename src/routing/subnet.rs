use crate::{config::validate_subnet, identity::NodeId};
use anyhow::{Result, ensure};
use ipnet::IpNet;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubnetDecision {
    ForwardVia(NodeId),
    Blocked(NodeId),
}

/// Publisher identity is retained through the overlay, even for identical CIDRs.
#[derive(Default)]
pub struct SubnetTable {
    advertised: BTreeSet<(NodeId, IpNet)>,
    selected: BTreeMap<IpNet, NodeId>,
    reachable: BTreeSet<NodeId>,
}

impl SubnetTable {
    pub fn advertise_verified(&mut self, publisher: NodeId, prefix: IpNet) -> Result<()> {
        validate_subnet(prefix)?;
        self.advertised.insert((publisher, prefix));
        Ok(())
    }

    pub fn accept(&mut self, prefix: IpNet, via: NodeId) -> Result<()> {
        ensure!(
            self.selected.get(&prefix).is_none_or(|old| *old == via),
            "prefix already accepted from another publisher; use explicit replacement"
        );
        self.replace(prefix, via)
    }

    pub fn replace(&mut self, prefix: IpNet, via: NodeId) -> Result<()> {
        ensure!(
            self.advertised.contains(&(via, prefix)),
            "publisher has not advertised this prefix"
        );
        self.selected.insert(prefix, via);
        Ok(())
    }

    pub fn withdraw(&mut self, publisher: NodeId, prefix: IpNet) {
        self.advertised.remove(&(publisher, prefix)); // Keep local intent; do not fall through.
    }

    pub fn unaccept(&mut self, prefix: IpNet) {
        self.selected.remove(&prefix);
    }

    pub fn set_reachable(&mut self, node: NodeId, reachable: bool) {
        if reachable {
            self.reachable.insert(node);
        } else {
            self.reachable.remove(&node);
        }
    }

    pub fn lookup(&self, address: IpAddr) -> Option<SubnetDecision> {
        let (prefix, via) = self
            .selected
            .iter()
            .filter(|(prefix, _)| prefix.contains(&address))
            .max_by_key(|(prefix, _)| prefix.prefix_len())?;
        Some(
            if self.advertised.contains(&(*via, *prefix)) && self.reachable.contains(via) {
                SubnetDecision::ForwardVia(*via)
            } else {
                SubnetDecision::Blocked(*via)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn same_prefix_never_fails_over_to_another_physical_lan() {
        let [b, c] = [1, 2].map(test_id);
        let prefix = "192.168.1.0/24".parse().unwrap();
        let host = "192.168.1.10".parse().unwrap();
        let mut table = SubnetTable::default();
        for node in [b, c] {
            table.advertise_verified(node, prefix).unwrap();
            table.set_reachable(node, true);
        }
        assert_eq!(table.lookup(host), None);
        table.accept(prefix, b).unwrap();
        assert!(table.accept(prefix, c).is_err());
        assert_eq!(table.lookup(host), Some(SubnetDecision::ForwardVia(b)));
        table.set_reachable(b, false);
        assert_eq!(table.lookup(host), Some(SubnetDecision::Blocked(b)));
        table.replace(prefix, c).unwrap();
        assert_eq!(table.lookup(host), Some(SubnetDecision::ForwardVia(c)));
        table.withdraw(c, prefix);
        assert_eq!(table.lookup(host), Some(SubnetDecision::Blocked(c)));
    }

    #[test]
    fn unavailable_more_specific_route_does_not_fall_through() {
        let mut table = SubnetTable::default();
        for (id, cidr) in [
            (test_id(1), "192.168.0.0/16"),
            (test_id(2), "192.168.1.0/24"),
        ] {
            let prefix = cidr.parse().unwrap();
            table.advertise_verified(id, prefix).unwrap();
            table.accept(prefix, id).unwrap();
        }
        table.set_reachable(test_id(1), true);
        assert_eq!(
            table.lookup("192.168.1.1".parse().unwrap()),
            Some(SubnetDecision::Blocked(test_id(2)))
        );
    }
}
