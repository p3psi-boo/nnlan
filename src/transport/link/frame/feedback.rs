//! Lossless batch-relative ACK encoding. No ACK thinning or time quantization.
use super::*;

const HEADER: usize = 26;
const ENTRY: usize = 11;

impl Frame {
    pub(in crate::transport::link) fn encode_compact_ack(&self) -> Option<Vec<u8>> {
        let Self::Ack(acks) = self else { return None };
        // One entry would be larger than the original format.
        if !(2..=MAX_FEEDBACK).contains(&acks.len()) {
            return None;
        }
        let sequence = acks.iter().map(|a| a.sequence).min()?;
        let sent = acks.iter().map(|a| a.sent_us).min()?;
        let received = acks.iter().map(|a| a.received_us).min()?;
        if acks.iter().any(|a| {
            a.sequence - sequence > u64::from(u16::MAX)
                || a.sent_us - sent > u64::from(u32::MAX)
                || a.received_us - received > u64::from(u32::MAX)
        }) {
            return None;
        }
        let mut out = Vec::with_capacity(HEADER + ENTRY * acks.len());
        out.extend_from_slice(&[7, acks.len() as u8]);
        for base in [sequence, sent, received] {
            out.extend_from_slice(&base.to_be_bytes());
        }
        for ack in acks {
            out.extend_from_slice(&((ack.sequence - sequence) as u16).to_be_bytes());
            out.extend_from_slice(&((ack.sent_us - sent) as u32).to_be_bytes());
            out.extend_from_slice(&((ack.received_us - received) as u32).to_be_bytes());
            out.push(match ack.arrival {
                Arrival::Original => 0,
                Arrival::Recovered => 1,
                Arrival::Retransmitted => 2,
            });
        }
        Some(out)
    }
    pub(super) fn decode_compact_ack(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= HEADER
                && (2..=MAX_FEEDBACK).contains(&usize::from(bytes[1]))
                && bytes.len() == HEADER + ENTRY * usize::from(bytes[1]),
            "compact ACK size"
        );
        let sequence = number(&bytes[2..10]);
        let sent = number(&bytes[10..18]);
        let received = number(&bytes[18..26]);
        let add = |base: u64, delta: u64| {
            base.checked_add(delta)
                .ok_or_else(|| anyhow::anyhow!("compact ACK overflow"))
        };
        let mut acks = Vec::with_capacity(usize::from(bytes[1]));
        for entry in bytes[HEADER..].chunks_exact(ENTRY) {
            let arrival = match entry[10] {
                0 => Arrival::Original,
                1 => Arrival::Recovered,
                2 => Arrival::Retransmitted,
                _ => bail!("ACK arrival"),
            };
            acks.push(Ack {
                sequence: add(
                    sequence,
                    u64::from(u16::from_be_bytes(entry[..2].try_into()?)),
                )?,
                sent_us: add(sent, u64::from(u32::from_be_bytes(entry[2..6].try_into()?)))?,
                received_us: add(
                    received,
                    u64::from(u32::from_be_bytes(entry[6..10].try_into()?)),
                )?,
                arrival,
            });
        }
        Ok(Self::Ack(acks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_timestamps_sparse_sequences_and_arrivals_roundtrip() {
        for count in [2, 20, 32] {
            let frame = Frame::Ack(
                (0..count)
                    .map(|i| Ack {
                        sequence: u64::MAX - 65_535 + i * 2000,
                        sent_us: u64::MAX - u64::from(u32::MAX) + (count - i) * 100,
                        received_us: 5_000_000_000 + i * 999,
                        arrival: [
                            Arrival::Original,
                            Arrival::Recovered,
                            Arrival::Retransmitted,
                        ][i as usize % 3],
                    })
                    .collect(),
            );
            let encoded = frame.encode_compact_ack().unwrap();
            assert_eq!(encoded.len(), HEADER + count as usize * ENTRY);
            assert_eq!(Frame::decode(&encoded).unwrap().encode(), frame.encode());
            for len in 0..encoded.len() {
                assert!(Frame::decode(&encoded[..len]).is_err());
            }
            let mut invalid = encoded.clone();
            invalid[HEADER + 10] = 3;
            assert!(Frame::decode(&invalid).is_err());
            for range in [2..10, 10..18, 18..26] {
                let mut overflow = encoded.clone();
                overflow[range].fill(255);
                assert!(Frame::decode(&overflow).is_err());
            }
        }
    }
    #[test]
    fn wide_deltas_and_single_acks_keep_original_format() {
        let a = Ack {
            sequence: 0,
            sent_us: 0,
            received_us: 0,
            arrival: Arrival::Original,
        };
        assert!(Frame::Ack(vec![a]).encode_compact_ack().is_none());
        for b in [
            Ack {
                sequence: 65_536,
                ..a
            },
            Ack {
                sent_us: 1 << 32,
                ..a
            },
            Ack {
                received_us: 1 << 32,
                ..a
            },
        ] {
            assert!(Frame::Ack(vec![a, b]).encode_compact_ack().is_none());
        }
    }
}
