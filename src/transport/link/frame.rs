//! Authenticated link payloads. All integers are big-endian; no native layouts.
use anyhow::{Result, bail, ensure};
mod feedback;

// Session header + AEAD tag + largest (source) frame header.
pub const DATAGRAM_OVERHEAD: usize = 24 + 16;
pub const SOURCE_HEADER: usize = 19;
pub const MIN_UDP: usize = 576 - 20 - 8;
pub const SHARD_BYTES: usize = crate::transport::wire::MAX_UDP - DATAGRAM_OVERHEAD - SOURCE_HEADER;
pub const MIN_SHARD_BYTES: usize = MIN_UDP - DATAGRAM_OVERHEAD - SOURCE_HEADER;
pub const MIN_FRAGMENT_BYTES: usize = MIN_SHARD_BYTES - FRAGMENT_HEADER;
pub const FRAGMENT_HEADER: usize = 23;
// Compact single-source tag 6 omits sequence (group + index), fragment index
// and count (0 / 1). Message ID, payload length and kind remain FEC-canonical.
pub const SINGLE_SAVING: usize = 12;
pub const FRAGMENT_BYTES: usize = SHARD_BYTES - FRAGMENT_HEADER;
pub const MAX_MESSAGE: usize = 32_768;
pub const MAX_FRAGMENTS: usize = MAX_MESSAGE.div_ceil(MIN_FRAGMENT_BYTES);
pub const MAX_K: usize = 8;
pub const MAX_M: usize = 4;
pub const MAX_FEEDBACK: usize = 32;
// IPv6 + UDP + session header + AEAD tag. IPv4 is conservatively charged the same.
pub const WIRE_OVERHEAD: usize = 40 + 8 + 24 + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arrival {
    Original,
    Recovered,
    Retransmitted,
}

#[derive(Clone, Copy, Debug)]
pub struct Ack {
    pub sequence: u64,
    pub sent_us: u64,
    pub received_us: u64,
    pub arrival: Arrival,
}

#[derive(Clone, Debug)]
pub enum Frame {
    Source {
        group: u64,
        index: u8,
        sent_us: u64,
        retransmitted: bool,
        shard: Vec<u8>,
    },
    Parity {
        group: u64,
        k: u8,
        m: u8,
        index: u8,
        shard: Vec<u8>,
    },
    Seal {
        group: u64,
        k: u8,
        m: u8,
    },
    Ack(Vec<Ack>),
    Nack(Vec<u64>),
}

fn number(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("length checked by decoder"))
}

impl Frame {
    pub(super) fn encoded_len(&self) -> usize {
        match self {
            Self::Source { shard, .. } => SOURCE_HEADER + shard.len(),
            Self::Parity { shard, .. } => 12 + shard.len(),
            Self::Seal { .. } => 11,
            Self::Ack(acks) => 2 + 25 * acks.len(),
            Self::Nack(ids) => 2 + 8 * ids.len(),
        }
    }

    /// Encode directly from the retransmission cache, without cloning its shard.
    pub(super) fn encode_source(
        group: u64,
        index: u8,
        sent_us: u64,
        retransmitted: bool,
        shard: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(SOURCE_HEADER + shard.len());
        out.push(1);
        out.extend_from_slice(&group.to_be_bytes());
        out.push(index);
        out.push(u8::from(retransmitted));
        out.extend_from_slice(&sent_us.to_be_bytes());
        out.extend_from_slice(shard);
        out
    }

    pub(super) fn encode_single_source(
        group: u64,
        index: u8,
        sent_us: u64,
        retransmitted: bool,
        shard: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(SOURCE_HEADER + shard.len() - SINGLE_SAVING);
        out.push(6);
        out.extend_from_slice(&group.to_be_bytes());
        out.push(index);
        out.push(u8::from(retransmitted));
        out.extend_from_slice(&sent_us.to_be_bytes());
        out.extend_from_slice(&shard[8..16]); // independent message replay ID
        out.extend_from_slice(&shard[20..]); // length, kind, payload
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        match self {
            Self::Source {
                group,
                index,
                sent_us,
                retransmitted,
                shard,
            } => {
                out.push(1);
                out.extend_from_slice(&group.to_be_bytes());
                out.push(*index);
                out.push(u8::from(*retransmitted));
                out.extend_from_slice(&sent_us.to_be_bytes());
                out.extend_from_slice(shard);
            }
            Self::Parity {
                group,
                k,
                m,
                index,
                shard,
            } => {
                out.push(2);
                out.extend_from_slice(&group.to_be_bytes());
                out.extend_from_slice(&[*k, *m, *index]);
                out.extend_from_slice(shard);
            }
            Self::Seal { group, k, m } => {
                out.push(3);
                out.extend_from_slice(&group.to_be_bytes());
                out.extend_from_slice(&[*k, *m]);
            }
            Self::Ack(acks) => {
                out.extend_from_slice(&[4, acks.len() as u8]);
                for ack in acks {
                    out.extend_from_slice(&ack.sequence.to_be_bytes());
                    out.extend_from_slice(&ack.sent_us.to_be_bytes());
                    out.extend_from_slice(&ack.received_us.to_be_bytes());
                    out.push(match ack.arrival {
                        Arrival::Original => 0,
                        Arrival::Recovered => 1,
                        Arrival::Retransmitted => 2,
                    });
                }
            }
            Self::Nack(ids) => {
                out.extend_from_slice(&[5, ids.len() as u8]);
                for id in ids {
                    out.extend_from_slice(&id.to_be_bytes());
                }
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= SHARD_BYTES + 19,
            "link frame size"
        );
        Ok(match bytes[0] {
            1 | 6 => {
                let compact = bytes[0] == 6;
                let saving = if compact { SINGLE_SAVING } else { 0 };
                ensure!(
                    (19 + FRAGMENT_HEADER - saving..=19 + SHARD_BYTES - saving)
                        .contains(&bytes.len()),
                    "source size"
                );
                ensure!(
                    usize::from(bytes[9]) < MAX_K && bytes[10] <= 1,
                    "source flags/index"
                );
                let group = number(&bytes[1..9]);
                let shard = if compact {
                    let sequence = group
                        .checked_add(u64::from(bytes[9]))
                        .ok_or_else(|| anyhow::anyhow!("source sequence overflow"))?;
                    let mut shard = Vec::with_capacity(bytes.len() - 19 + SINGLE_SAVING);
                    shard.extend_from_slice(&sequence.to_be_bytes());
                    shard.extend_from_slice(&bytes[19..27]);
                    shard.extend_from_slice(&[0, 0, 0, 1]);
                    shard.extend_from_slice(&bytes[27..]);
                    shard
                } else {
                    bytes[19..].to_vec()
                };
                let fragment = Fragment::decode(&shard)?;
                ensure!(
                    group.checked_add(u64::from(bytes[9])) == Some(fragment.sequence),
                    "source sequence/group mismatch"
                );
                Self::Source {
                    group,
                    index: bytes[9],
                    sent_us: number(&bytes[11..19]),
                    retransmitted: bytes[10] != 0,
                    shard,
                }
            }
            2 => {
                ensure!(
                    (MIN_SHARD_BYTES + 12..=SHARD_BYTES + 12).contains(&bytes.len()),
                    "parity size"
                );
                validate_group(bytes[9], bytes[10])?;
                ensure!(bytes[10] > 0 && bytes[11] < bytes[10], "parity index");
                Self::Parity {
                    group: number(&bytes[1..9]),
                    k: bytes[9],
                    m: bytes[10],
                    index: bytes[11],
                    shard: bytes[12..].to_vec(),
                }
            }
            3 => {
                ensure!(bytes.len() == 11, "seal size");
                validate_group(bytes[9], bytes[10])?;
                Self::Seal {
                    group: number(&bytes[1..9]),
                    k: bytes[9],
                    m: bytes[10],
                }
            }
            4 => {
                ensure!(
                    bytes.len() >= 2
                        && usize::from(bytes[1]) <= MAX_FEEDBACK
                        && bytes.len() == 2 + usize::from(bytes[1]) * 25,
                    "ack size"
                );
                let mut acks = Vec::with_capacity(usize::from(bytes[1]));
                for entry in bytes[2..].chunks_exact(25) {
                    let arrival = match entry[24] {
                        0 => Arrival::Original,
                        1 => Arrival::Recovered,
                        2 => Arrival::Retransmitted,
                        _ => bail!("ack arrival"),
                    };
                    acks.push(Ack {
                        sequence: number(&entry[..8]),
                        sent_us: number(&entry[8..16]),
                        received_us: number(&entry[16..24]),
                        arrival,
                    });
                }
                Self::Ack(acks)
            }
            5 => {
                ensure!(
                    bytes.len() >= 2
                        && usize::from(bytes[1]) <= MAX_FEEDBACK
                        && bytes.len() == 2 + usize::from(bytes[1]) * 8,
                    "nack size"
                );
                Self::Nack(bytes[2..].chunks_exact(8).map(number).collect())
            }
            7 => Self::decode_compact_ack(bytes)?,
            _ => bail!("unknown link frame"),
        })
    }
}

fn validate_group(k: u8, m: u8) -> Result<()> {
    ensure!(
        (1..=MAX_K).contains(&usize::from(k)) && usize::from(m) <= MAX_M,
        "FEC dimensions"
    );
    Ok(())
}

pub struct Fragment<'a> {
    pub sequence: u64,
    pub message: u64,
    pub index: usize,
    pub count: usize,
    pub kind: u8,
    pub payload: &'a [u8],
}
impl Fragment<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER + self.payload.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.message.to_be_bytes());
        out.extend_from_slice(&(self.index as u16).to_be_bytes());
        out.extend_from_slice(&(self.count as u16).to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(self.payload);
        out
    }
}
impl<'a> Fragment<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        ensure!(
            (FRAGMENT_HEADER..=SHARD_BYTES).contains(&bytes.len()),
            "fragment size"
        );
        let index = usize::from(u16::from_be_bytes(bytes[16..18].try_into()?));
        let count = usize::from(u16::from_be_bytes(bytes[18..20].try_into()?));
        let len = usize::from(u16::from_be_bytes(bytes[20..22].try_into()?));
        ensure!(
            (1..=MAX_FRAGMENTS).contains(&count)
                && index < count
                && len > 0
                && len <= FRAGMENT_BYTES
                && FRAGMENT_HEADER + len <= bytes.len(),
            "fragment dimensions"
        );
        ensure!(
            index + 1 == count || len >= MIN_FRAGMENT_BYTES,
            "short interior fragment"
        );
        ensure!(
            (count - 1) * MIN_FRAGMENT_BYTES < MAX_MESSAGE,
            "message size"
        );
        ensure!(
            index + 1 != count || (count - 1) * MIN_FRAGMENT_BYTES + len <= MAX_MESSAGE,
            "message size"
        );
        ensure!(
            bytes[FRAGMENT_HEADER + len..].iter().all(|b| *b == 0),
            "fragment padding"
        );
        Ok(Self {
            sequence: number(&bytes[..8]),
            message: number(&bytes[8..16]),
            index,
            count,
            kind: bytes[22],
            payload: &bytes[FRAGMENT_HEADER..FRAGMENT_HEADER + len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_single_sources_are_canonical_and_strict() {
        for size in [1, 300, FRAGMENT_BYTES] {
            for retry in [false, true] {
                let shard = Fragment {
                    sequence: 47,
                    message: 39,
                    index: 0,
                    count: 1,
                    kind: 2,
                    payload: &vec![7; size],
                }
                .encode();
                let compact = Frame::encode_single_source(40, 7, 123, retry, &shard);
                let full = Frame::encode_source(40, 7, 123, retry, &shard);
                assert_eq!(compact.len() + SINGLE_SAVING, full.len());
                assert_eq!(Frame::decode(&compact).unwrap().encode(), full);
                for len in 0..compact.len() {
                    assert!(Frame::decode(&compact[..len]).is_err());
                }
                for (offset, value) in [(9, 8), (10, 2), (27, 255), (28, 0)] {
                    let mut bad = compact.clone();
                    bad[offset] = value;
                    assert!(Frame::decode(&bad).is_err());
                }
                let mut overflow = compact.clone();
                overflow[1..9].fill(255);
                assert!(Frame::decode(&overflow).is_err());
                let mut bad = compact.clone();
                bad.push(1);
                assert!(Frame::decode(&bad).is_err());
            }
        }
    }

    #[test]
    fn allocation_free_lengths_and_borrowed_source_match_wire_bytes() {
        for size in [FRAGMENT_HEADER + 1, MIN_SHARD_BYTES, SHARD_BYTES] {
            let shard: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            for retransmitted in [false, true] {
                let frame = Frame::Source {
                    group: 123,
                    index: 7,
                    sent_us: 456,
                    retransmitted,
                    shard: shard.clone(),
                };
                assert_eq!(frame.encoded_len(), frame.encode().len());
                assert_eq!(
                    Frame::encode_source(123, 7, 456, retransmitted, &shard),
                    frame.encode()
                );
            }
            let frame = Frame::Parity {
                group: 123,
                k: 8,
                m: 2,
                index: 1,
                shard,
            };
            assert_eq!(frame.encoded_len(), frame.encode().len());
        }
        let seal = Frame::Seal {
            group: 123,
            k: 8,
            m: 2,
        };
        assert_eq!(seal.encoded_len(), seal.encode().len());
        for count in 0..=MAX_FEEDBACK {
            let acks = Frame::Ack(vec![
                Ack {
                    sequence: 7,
                    sent_us: 9,
                    received_us: 11,
                    arrival: Arrival::Original
                };
                count
            ]);
            let nacks = Frame::Nack(vec![7; count]);
            assert_eq!(acks.encoded_len(), acks.encode().len());
            assert_eq!(nacks.encoded_len(), nacks.encode().len());
        }
    }
    #[test]
    fn malformed_input_is_bounded_and_never_panics() {
        for tag in 0..=255 {
            for len in 0..=SHARD_BYTES + 20 {
                let _ = Frame::decode(&vec![tag; len]);
            }
        }
    }
    #[test]
    fn source_frames_fit_each_proven_ipv6_path_size() {
        for (limit, mtu) in [
            (crate::transport::wire::BASE_UDP, 1280),
            (crate::transport::wire::MAX_UDP, 1500),
        ] {
            let frame = Frame::Source {
                group: 0,
                index: 0,
                sent_us: 0,
                retransmitted: false,
                shard: Fragment {
                    sequence: 0,
                    message: 0,
                    index: 0,
                    count: 1,
                    kind: 2,
                    payload: &vec![7; limit - DATAGRAM_OVERHEAD - SOURCE_HEADER - FRAGMENT_HEADER],
                }
                .encode(),
            };
            assert_eq!(frame.encode().len() + WIRE_OVERHEAD, mtu);
            assert!(Frame::decode(&frame.encode()).is_ok());
        }
    }
}
