use super::{LinkStats, Message, frame::*};
use crate::protocol::{ReplayWindow, TransmissionNumber};
use anyhow::{Result, ensure};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const MAX_GROUPS: usize = 128;
const MAX_ASSEMBLIES: usize = 128;
const RECEIVE_TTL: Duration = Duration::from_secs(1);
const NACK_DELAY: Duration = Duration::from_millis(8);

struct Group {
    shards: Vec<Option<Vec<u8>>>,
    k: Option<usize>,
    m: usize,
    created: Instant,
    last_nack: Option<Instant>,
    nacks: u8,
    shard_bytes: Option<usize>,
}

impl Group {
    fn new(now: Instant) -> Self {
        Self {
            shards: vec![None; MAX_K + MAX_M],
            k: None,
            m: 0,
            created: now,
            last_nack: None,
            nacks: 0,
            shard_bytes: None,
        }
    }
    fn dimensions(&mut self, k: u8, m: u8) -> Result<()> {
        let k = usize::from(k);
        let m = usize::from(m);
        if let Some(old) = self.k {
            ensure!(old == k && self.m == m, "FEC dimensions changed");
        } else {
            ensure!(
                self.shards[k..MAX_K].iter().all(Option::is_none),
                "FEC seal truncates known sources"
            );
            self.k = Some(k);
            self.m = m;
        }
        Ok(())
    }
}
struct Assembly {
    bytes: usize,
    stride: Option<usize>,
    kind: u8,
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    created: Instant,
}

#[derive(Default)]
pub struct Receiver {
    groups: BTreeMap<u64, Group>,
    assemblies: BTreeMap<u64, Assembly>,
    group_ids: ReplayWindow,
    source_ids: ReplayWindow,
    message_ids: ReplayWindow,
    acks: BTreeMap<u64, Ack>,
    codecs: BTreeMap<(usize, usize), ReedSolomon>,
}

impl Receiver {
    pub fn source(
        &mut self,
        group: u64,
        index: u8,
        shard: Vec<u8>,
        ack: Ack,
        now: Instant,
        stats: &mut LinkStats,
    ) -> Result<Vec<Message>> {
        self.ack(ack);
        let message = self.fragment(&shard, now)?;
        if self.group(group, now).is_some() {
            let state = self.groups.get_mut(&group).expect("group just created");
            ensure!(
                state.k.is_none_or(|k| usize::from(index) < k),
                "source beyond seal"
            );
            let mut padded = shard;
            if let Some(size) = state.shard_bytes {
                ensure!(padded.len() <= size, "source exceeds parity shard size");
                padded.resize(size, 0);
            }
            let slot = &mut state.shards[usize::from(index)];
            if let Some(old) = slot {
                ensure!(*old == padded, "conflicting source shard");
            } else {
                *slot = Some(padded);
            }
        }
        let mut result = self.recover(group, now, stats)?;
        if let Some(message) = message {
            result.insert(0, message);
        }
        Ok(result)
    }

    fn group(&mut self, id: u64, now: Instant) -> Option<&mut Group> {
        if !self.groups.contains_key(&id) {
            if self.groups.len() >= MAX_GROUPS
                || !self.group_ids.record_authenticated(TransmissionNumber(id))
            {
                return None;
            }
            self.groups.insert(id, Group::new(now));
        }
        self.groups.get_mut(&id)
    }
    pub fn parity(
        &mut self,
        group: u64,
        k: u8,
        m: u8,
        parity: Option<(u8, Vec<u8>)>,
        now: Instant,
        stats: &mut LinkStats,
    ) -> Result<Vec<Message>> {
        let Some(state) = self.group(group, now) else {
            return Ok(vec![]);
        };
        ensure!(
            group.checked_add(u64::from(k)).is_some(),
            "FEC group sequence overflow"
        );
        state.dimensions(k, m)?;
        if let Some((index, shard)) = parity {
            if let Some(size) = state.shard_bytes {
                ensure!(size == shard.len(), "parity shard size changed");
            } else {
                ensure!(
                    state.shards[..usize::from(k)]
                        .iter()
                        .flatten()
                        .all(|s| s.len() <= shard.len()),
                    "parity truncates source"
                );
                state.shard_bytes = Some(shard.len());
                for source in state.shards[..usize::from(k)].iter_mut().flatten() {
                    source.resize(shard.len(), 0);
                }
            }
            let slot = &mut state.shards[usize::from(k) + usize::from(index)];
            if let Some(old) = slot {
                ensure!(*old == shard, "conflicting parity shard");
            } else {
                *slot = Some(shard);
            }
        }
        self.recover(group, now, stats)
    }

    fn recover(&mut self, id: u64, now: Instant, stats: &mut LinkStats) -> Result<Vec<Message>> {
        let Some(group) = self.groups.get_mut(&id) else {
            return Ok(vec![]);
        };
        let Some(k) = group.k else {
            return Ok(vec![]);
        };
        let missing: Vec<_> = (0..k).filter(|&i| group.shards[i].is_none()).collect();
        if missing.is_empty() {
            self.groups.remove(&id);
            return Ok(vec![]);
        }
        if group.m == 0
            || group.shards[..k + group.m]
                .iter()
                .filter(|s| s.is_some())
                .count()
                < k
        {
            return Ok(vec![]);
        }
        let codec = self
            .codecs
            .entry((k, group.m))
            .or_insert_with(|| ReedSolomon::new(k, group.m).expect("validated FEC dimensions"));
        codec.reconstruct_data(&mut group.shards[..k + group.m])?;
        let mut restored = Vec::with_capacity(missing.len());
        for index in missing {
            let shard = group.shards[index].take().expect("reconstructed source");
            let fragment = Fragment::decode(&shard)?;
            ensure!(
                fragment.sequence == id + index as u64,
                "reconstructed sequence mismatch"
            );
            restored.push((fragment.sequence, shard));
        }
        self.groups.remove(&id);
        let mut result = vec![];
        for (sequence, shard) in restored {
            self.ack(Ack {
                sequence,
                sent_us: 0,
                received_us: 0,
                arrival: Arrival::Recovered,
            });
            if let Some(message) = self.fragment(&shard, now)? {
                result.push(message);
            }
            stats.fec_recovered += 1;
        }
        Ok(result)
    }

    fn fragment(&mut self, bytes: &[u8], now: Instant) -> Result<Option<Message>> {
        let f = Fragment::decode(bytes)?;
        if !self
            .source_ids
            .record_authenticated(TransmissionNumber(f.sequence))
            || !self.message_ids.would_accept(TransmissionNumber(f.message))
        {
            return Ok(None);
        }
        // The common IP packet fits one source frame. It still passes fragment
        // validation and both replay windows, but needs no reassembly allocation.
        // An existing partial message must take the checked slow path: a peer
        // cannot change its dimensions/kind by relabelling the last fragment.
        if f.count == 1 && !self.assemblies.contains_key(&f.message) {
            self.message_ids
                .record_authenticated(TransmissionNumber(f.message));
            return Ok(Some(Message {
                kind: f.kind,
                payload: f.payload.to_vec(),
            }));
        }
        if !self.assemblies.contains_key(&f.message) {
            ensure!(
                self.assemblies.len() < MAX_ASSEMBLIES,
                "link reassembly capacity"
            );
            self.assemblies.insert(
                f.message,
                Assembly {
                    kind: f.kind,
                    bytes: 0,
                    stride: None,
                    chunks: vec![None; f.count],
                    received: 0,
                    created: now,
                },
            );
        }
        let assembly = self
            .assemblies
            .get_mut(&f.message)
            .expect("assembly inserted");
        ensure!(
            assembly.chunks.len() == f.count && assembly.kind == f.kind,
            "fragment metadata changed"
        );
        ensure!(
            assembly.bytes + f.payload.len() <= MAX_MESSAGE,
            "assembled message size"
        );
        if f.index + 1 != f.count {
            if let Some(stride) = assembly.stride {
                ensure!(stride == f.payload.len(), "fragment stride changed");
            }
            ensure!(
                (f.count - 1) * f.payload.len() < MAX_MESSAGE,
                "message dimensions"
            );
            if let Some(last) = &assembly.chunks[f.count - 1] {
                ensure!(last.len() <= f.payload.len(), "oversized final fragment");
            }
            assembly.stride = Some(f.payload.len());
        } else if let Some(stride) = assembly.stride {
            ensure!(f.payload.len() <= stride, "oversized final fragment");
        }
        let slot = &mut assembly.chunks[f.index];
        ensure!(slot.is_none(), "fragment reused with a different sequence");
        *slot = Some(f.payload.to_vec());
        assembly.received += 1;
        assembly.bytes += f.payload.len();
        if assembly.received != f.count {
            return Ok(None);
        }
        let assembly = self
            .assemblies
            .remove(&f.message)
            .expect("complete assembly");
        self.message_ids
            .record_authenticated(TransmissionNumber(f.message));
        let mut payload = Vec::with_capacity(assembly.bytes);
        for chunk in assembly.chunks {
            payload.extend_from_slice(&chunk.expect("complete fragment"));
        }
        Ok(Some(Message {
            kind: assembly.kind,
            payload,
        }))
    }

    fn ack(&mut self, ack: Ack) {
        if self.acks.len() >= 2048 && !self.acks.contains_key(&ack.sequence) {
            return;
        }
        // Prefer evidence of actual original delivery over a reconstruction report.
        self.acks
            .entry(ack.sequence)
            .and_modify(|old| {
                if ack.arrival == Arrival::Original {
                    *old = ack;
                }
            })
            .or_insert(ack);
    }
    pub fn feedback(&mut self, now: Instant) -> Vec<Frame> {
        self.groups
            .retain(|_, g| now.saturating_duration_since(g.created) < RECEIVE_TTL);
        self.assemblies
            .retain(|_, a| now.saturating_duration_since(a.created) < RECEIVE_TTL);
        let mut result = vec![];
        // Per-tick limit bounds CPU and control traffic under malicious authenticated peers.
        for _ in 0..8 {
            let mut acks = vec![];
            for _ in 0..MAX_FEEDBACK {
                if let Some((_, ack)) = self.acks.pop_first() {
                    acks.push(ack);
                } else {
                    break;
                }
            }
            if acks.is_empty() {
                break;
            }
            result.push(Frame::Ack(acks));
        }
        let mut missing = vec![];
        for (&id, group) in &mut self.groups {
            let Some(k) = group.k else {
                continue;
            };
            if group.nacks >= 2
                || now.saturating_duration_since(group.created) < NACK_DELAY
                || group
                    .last_nack
                    .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_millis(50))
            {
                continue;
            }
            for index in 0..k {
                if group.shards[index].is_none() {
                    missing.push(id + index as u64);
                }
            }
            group.last_nack = Some(now);
            group.nacks += 1;
            if missing.len() >= MAX_FEEDBACK {
                break;
            }
        }
        for chunk in missing.chunks(MAX_FEEDBACK) {
            result.push(Frame::Nack(chunk.to_vec()));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(
        sequence: u64,
        message: u64,
        index: usize,
        count: usize,
        payload: &[u8],
    ) -> Vec<u8> {
        Fragment {
            sequence,
            message,
            index,
            count,
            kind: 2,
            payload,
        }
        .encode()
    }

    #[test]
    fn single_fragment_fast_path_preserves_replay_and_never_allocates_an_assembly() {
        let now = Instant::now();
        let mut receiver = Receiver::default();
        // More than one complete replay-window wrap, including reordered messages.
        for pair in 0..5000 {
            for id in [pair * 2 + 2, pair * 2 + 1] {
                let bytes = fragment(id, id, 0, 1, b"payload");
                let message = receiver.fragment(&bytes, now).unwrap().unwrap();
                assert_eq!(message.kind, 2);
                assert_eq!(message.payload, b"payload");
                assert!(receiver.assemblies.is_empty());
                assert!(receiver.fragment(&bytes, now).unwrap().is_none());
            }
        }
        // A fresh source number does not redeliver an already completed message.
        assert!(
            receiver
                .fragment(&fragment(10001, 10000, 0, 1, b"changed"), now)
                .unwrap()
                .is_none()
        );
        assert!(
            receiver
                .fragment(&fragment(10002, 1, 0, 1, b"too old"), now)
                .unwrap()
                .is_none()
        );
        let mut invalid = fragment(10003, 10003, 0, 1, b"bad");
        invalid[16..18].copy_from_slice(&1_u16.to_be_bytes());
        assert!(receiver.fragment(&invalid, now).is_err());
    }

    #[test]
    fn single_fragment_cannot_replace_an_incomplete_multi_fragment_message() {
        let now = Instant::now();
        let mut receiver = Receiver::default();
        let interior = vec![17; FRAGMENT_BYTES];
        assert!(
            receiver
                .fragment(&fragment(1, 1, 0, 2, &interior), now)
                .unwrap()
                .is_none()
        );
        assert!(
            receiver
                .fragment(&fragment(2, 1, 0, 1, b"replacement"), now)
                .is_err()
        );
        let message = receiver
            .fragment(&fragment(3, 1, 1, 2, b"tail"), now)
            .unwrap()
            .unwrap();
        assert_eq!(message.payload, [interior, b"tail".to_vec()].concat());
        assert!(receiver.assemblies.is_empty());
    }
}
