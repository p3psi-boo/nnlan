//! Deterministic candidates and collision resolution over verified address claims.
//! This module does not distribute, authenticate or persist claims itself.

use crate::identity::NodeId;
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub const IPV4_POOL: &str = "33.0.0.0/8";
pub const IPV6_POOL: &str = "fd33::/16";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AddressCandidate {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    /// Persist this counter before advertising the corresponding IPv4 claim.
    pub probe: u32,
}

pub fn candidate(node: NodeId, probe: u32) -> AddressCandidate {
    let mut material = [0; 36];
    material[..32].copy_from_slice(node.as_bytes());
    material[32..].copy_from_slice(&probe.to_be_bytes());
    // Frozen protocol domain: product renaming must preserve addresses and peer compatibility.
    let v4 = blake3::derive_key("ggbond.ipv4-candidate.v1", &material);
    let v6 = blake3::derive_key("ggbond.ipv6-address.v1", node.as_bytes());
    let mut bytes = [0; 16];
    bytes[..2].copy_from_slice(&[0xfd, 0x33]);
    bytes[2..].copy_from_slice(&v6[..14]);
    AddressCandidate {
        ipv4: Ipv4Addr::new(33, v4[0], v4[1], v4[2]),
        ipv6: bytes.into(),
        probe,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AddressClaim {
    pub owner: NodeId,
    /// None is a versioned withdrawal, retained to reject delayed old claims.
    pub address: Option<Ipv4Addr>,
    pub version: u64,
}

pub struct ClaimTable {
    claims: BTreeMap<NodeId, AddressClaim>,
    capacity: usize,
}

impl ClaimTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            claims: BTreeMap::new(),
            capacity,
        }
    }

    pub fn apply_verified(&mut self, claim: AddressClaim) -> Result<bool> {
        ensure!(
            claim.address.is_none_or(|ip| ip.octets()[0] == 33),
            "claim is outside {IPV4_POOL}"
        );
        if let Some(old) = self.claims.get(&claim.owner) {
            if claim.version <= old.version {
                return Ok(false);
            }
        } else {
            ensure!(
                self.claims.len() < self.capacity,
                "address claim table is full"
            );
        }
        self.claims.insert(claim.owner, claim);
        Ok(true)
    }

    /// Deterministic across insertion orders; full public keys break ties.
    pub fn owner(&self, address: Ipv4Addr) -> Option<NodeId> {
        self.claims
            .values()
            .find(|claim| claim.address == Some(address))
            .map(|c| c.owner)
    }

    pub fn resolve(
        &self,
        node: NodeId,
        start_probe: u32,
        attempts: u32,
    ) -> Result<AddressCandidate> {
        let mut probe = start_probe;
        for attempt in 0..attempts {
            let next = candidate(node, probe);
            if self.owner(next.ipv4).is_none_or(|owner| node <= owner) {
                return Ok(next);
            }
            if attempt + 1 < attempts {
                probe = probe
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("address probe counter exhausted"))?;
            }
        }
        bail!("address candidate retry budget exhausted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn pools_stability_and_ipv6_independent_of_collision_counter() {
        let a = candidate(test_id(1), 0);
        let b = candidate(test_id(1), 1);
        assert_eq!(a, candidate(test_id(1), 0));
        assert_eq!(a.ipv4.octets()[0], 33);
        assert_eq!(&a.ipv6.octets()[..2], &[0xfd, 0x33]);
        assert_eq!(a.ipv6, b.ipv6);
        assert_ne!(a.ipv4, b.ipv4);
    }

    #[test]
    fn collision_has_same_winner_after_partition_merge() {
        let low = test_id(1).min(test_id(2));
        let high = test_id(1).max(test_id(2));
        let conflict = candidate(high, 0).ipv4;
        let mut table = ClaimTable::new(2);
        for owner in [high, low] {
            table
                .apply_verified(AddressClaim {
                    owner,
                    address: Some(conflict),
                    version: 1,
                })
                .unwrap();
        }
        assert_eq!(table.owner(conflict), Some(low));
        let resolved = table.resolve(high, 0, 16).unwrap();
        assert_ne!(resolved.ipv4, conflict);
        assert!(resolved.probe > 0);
        table
            .apply_verified(AddressClaim {
                owner: high,
                address: Some(resolved.ipv4),
                version: 2,
            })
            .unwrap();
        assert_eq!(table.owner(resolved.ipv4), Some(high));
    }

    #[test]
    fn stale_withdrawals_and_capacity() {
        let mut table = ClaimTable::new(1);
        let owner = test_id(1);
        let old = AddressClaim {
            owner,
            address: Some(candidate(owner, 0).ipv4),
            version: 1,
        };
        table.apply_verified(old).unwrap();
        table
            .apply_verified(AddressClaim {
                address: None,
                version: 2,
                ..old
            })
            .unwrap();
        assert!(!table.apply_verified(old).unwrap());
        assert!(table.owner(old.address.unwrap()).is_none());
        assert!(
            table
                .apply_verified(AddressClaim {
                    owner: test_id(2),
                    ..old
                })
                .is_err()
        );
        assert!(table.resolve(owner, 0, 0).is_err());
    }
}
