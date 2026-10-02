use crate::identity::NodeId;
use anyhow::{Result, ensure};

pub const MAGIC: &[u8; 4] = b"GGB3";
/// Original GGB3 ceiling, also the IPv6 minimum MTU minus IP/UDP headers.
pub const BASE_UDP: usize = 1232;
/// Fits a 1500-byte path even with IPv6. Only an authenticated size probe
/// permits sending this much; changing the ceiling never raises a live path.
pub const MAX_UDP: usize = 1452;
pub const ENVELOPE_HEADER: usize = 66;
pub const LINK_SCOPE: u8 = 0;
pub const HS1: u8 = 1;
pub const HS2: u8 = 2;
pub const HS3: u8 = 3;
pub const DATA: u8 = 4;
pub const TRACE: u8 = 5;
pub const TRACE_REPLY: u8 = 6;
pub const PUNCH: u8 = 7;
/// Authenticated proof that the responder installed the new transport keys.
pub const READY: u8 = 8;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub source: NodeId,
    pub destination: NodeId,
    pub hops: u8,
    pub kind: u8,
    pub body: Vec<u8>,
}

impl Envelope {
    /// Only a direct DATA message can elide identities. The authenticated
    /// neighbor becomes the origin and this node the terminal destination.
    pub(crate) fn is_direct_data(&self, local: NodeId, next: NodeId) -> bool {
        self.kind == DATA && self.source == local && self.destination == next
    }
    pub(crate) fn from_direct(source: NodeId, local: NodeId, body: Vec<u8>) -> Result<Self> {
        ensure!(
            !body.is_empty() && body.len() <= 32_768 - ENVELOPE_HEADER,
            "direct data size"
        );
        Ok(Self {
            source,
            destination: local,
            hops: 1,
            kind: DATA,
            body,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_HEADER + self.body.len());
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.destination.as_bytes());
        out.extend_from_slice(&[self.hops, self.kind]);
        out.extend_from_slice(&self.body);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_with(bytes, |_| None)
    }

    /// Reuse validated identities from the caller's bounded membership table.
    /// A lookup miss still performs full key validation; this is not admission
    /// or source authentication. The runtime checks both independently.
    pub(crate) fn decode_with(
        bytes: &[u8],
        mut known: impl FnMut(&[u8; 32]) -> Option<NodeId>,
    ) -> Result<Self> {
        ensure!(
            (ENVELOPE_HEADER..=32_768).contains(&bytes.len()),
            "invalid envelope size"
        );
        ensure!(
            matches!(bytes[65], DATA | TRACE | TRACE_REPLY),
            "unsupported envelope kind"
        );
        let mut identity = |raw: [u8; 32]| -> Result<NodeId> {
            match known(&raw) {
                Some(node) => {
                    ensure!(node.as_bytes() == &raw, "identity lookup mismatch");
                    Ok(node)
                }
                None => NodeId::from_bytes(raw),
            }
        };
        Ok(Self {
            source: identity(bytes[..32].try_into()?)?,
            destination: identity(bytes[32..64].try_into()?)?,
            hops: bytes[64],
            kind: bytes[65],
            body: bytes[66..].to_vec(),
        })
    }
}

pub fn session_packet(kind: u8, scope: u8, session: u64, number: u64, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(24 + body.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&[kind, scope, 0, 0]);
    packet.extend_from_slice(&session.to_be_bytes());
    packet.extend_from_slice(&number.to_be_bytes());
    packet.extend_from_slice(body);
    packet
}

pub struct Packet<'a> {
    pub kind: u8,
    pub scope: u8,
    pub session: u64,
    pub number: u64,
    pub body: &'a [u8],
}
impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 24 && &bytes[..4] == MAGIC && bytes[6..8] == [0, 0],
            "invalid wire header"
        );
        ensure!(
            matches!(bytes[4], HS1 | HS2 | HS3 | DATA | READY) && bytes[5] == LINK_SCOPE,
            "unsupported wire packet"
        );
        Ok(Self {
            kind: bytes[4],
            scope: bytes[5],
            session: u64::from_be_bytes(bytes[8..16].try_into()?),
            number: u64::from_be_bytes(bytes[16..24].try_into()?),
            body: &bytes[24..],
        })
    }
}

pub fn random_id() -> Result<u64> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;
    use std::collections::BTreeSet;

    #[test]
    fn direct_identity_elision_is_terminal_data_only() {
        let a = test_id(1);
        let b = test_id(2);
        let c = test_id(3);
        let envelope = Envelope::from_direct(a, b, vec![0, 9]).unwrap();
        assert_eq!(envelope.source, a);
        assert_eq!(envelope.destination, b);
        assert_eq!(envelope.hops, 1);
        assert!(envelope.is_direct_data(a, b));
        assert!(!envelope.is_direct_data(a, c)); // needs a relay
        assert!(!envelope.is_direct_data(c, b)); // this node is a relay
        for kind in [TRACE, TRACE_REPLY] {
            assert!(
                !Envelope {
                    kind,
                    ..envelope.clone()
                }
                .is_direct_data(a, b)
            );
        }
        assert!(Envelope::from_direct(a, b, vec![]).is_err());
        assert!(Envelope::from_direct(a, b, vec![0; 32_768]).is_err());
    }

    #[test]
    fn v3_rejects_legacy_versions_scopes_and_nested_handshakes() {
        let packet = session_packet(HS1, LINK_SCOPE, 7, 0, &[0; 256]);
        assert!(Packet::parse(&packet).is_ok());
        for version in [b"GGB1", b"GGB2"] {
            let mut old = packet.clone();
            old[..4].copy_from_slice(version);
            assert!(Packet::parse(&old).is_err());
        }
        for scope in 1..=255 {
            let mut old = packet.clone();
            old[5] = scope;
            assert!(Packet::parse(&old).is_err());
        }
        for kind in [HS1, HS2, HS3, READY, PUNCH, 0, 255] {
            let old = Envelope {
                source: test_id(1),
                destination: test_id(2),
                hops: 32,
                kind,
                body: packet.clone(),
            };
            assert!(Envelope::decode(&old.encode()).is_err());
        }
    }

    #[test]
    fn known_identity_decode_matches_strict_decode_and_preserves_bytes() {
        let ids: BTreeSet<_> = (1..=64).map(test_id).collect();
        for source in &ids {
            let original = Envelope {
                source: *source,
                destination: test_id(77), // Also exercise validated lookup misses.
                hops: 17,
                kind: DATA,
                body: (0..=255).collect(),
            };
            let bytes = original.encode();
            let strict = Envelope::decode(&bytes).unwrap();
            let mut hits = 0;
            let reused = Envelope::decode_with(&bytes, |raw| {
                let node = ids.get(raw).copied();
                hits += usize::from(node.is_some());
                node
            })
            .unwrap();
            assert_eq!(hits, 1);
            assert_eq!(strict.encode(), bytes);
            assert_eq!(reused.encode(), bytes);
        }
    }

    #[test]
    fn known_identity_decode_does_not_accept_invalid_or_substituted_keys() {
        let a = test_id(1);
        let b = test_id(2);
        let known = BTreeSet::from([a, b]);
        let mut bytes = Envelope {
            source: a,
            destination: b,
            hops: 32,
            kind: DATA,
            body: vec![],
        }
        .encode();
        assert!(Envelope::decode_with(&bytes, |_| Some(b)).is_err());
        for length in 0..ENVELOPE_HEADER {
            assert!(Envelope::decode_with(&bytes[..length], |_| panic!("short input")).is_err());
        }
        let oversized = vec![0; 32_769];
        assert!(Envelope::decode_with(&oversized, |_| panic!("oversized input")).is_err());

        // Both weak points and arbitrary encodings follow the original strict
        // path on misses; a byte-key lookup never admits an unchecked identity.
        let mut random = 7_u64;
        for offset in [0, 32] {
            for trial in 0..256 {
                for byte in &mut bytes[offset..offset + 32] {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *byte = if trial == 0 { 0 } else { random as u8 };
                }
                let strict = Envelope::decode(&bytes);
                let reused = Envelope::decode_with(&bytes, |raw| known.get(raw).copied());
                assert_eq!(strict.is_ok(), reused.is_ok());
                if trial == 0 {
                    assert!(reused.is_err());
                }
                if let Ok(decoded) = reused {
                    assert_eq!(decoded.encode(), bytes);
                }
            }
            bytes[..32].copy_from_slice(a.as_bytes());
        }
    }
}
