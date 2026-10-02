use super::{
    LinkStats, Message,
    cache::{CacheBudget, MAX_SOURCES, Reservation},
    controller::{Class, Controller, FeedbackClock},
    frame::*,
};
use crate::config::RepairConfig;
use anyhow::{Result, ensure};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

pub const MAX_QUEUE: usize = 2048;
const MAX_CONTROL_QUEUE: usize = 128;
const LIFETIME: Duration = Duration::from_secs(1);
const SOURCE_QUEUE_LIFETIME: Duration = Duration::from_millis(250);
pub const GROUP_WAIT: Duration = Duration::from_millis(2);

struct Source {
    _reservation: Reservation,
    group: u64,
    index: u8,
    shard: Vec<u8>,
    compact: bool,
    created: Instant,
    first_sent: Option<Instant>,
    last_sent: Option<Instant>,
    // One original plus at most two retransmissions, not a heap allocation per source.
    stamps: [u64; 3],
    attempts: u8,
    scheduled: bool,
    retry_after: Instant,
}
impl Source {
    fn wire_bytes(&self) -> usize {
        self.shard.len() + SOURCE_HEADER + WIRE_OVERHEAD
            - if self.compact { SINGLE_SAVING } else { 0 }
    }
}
enum Item {
    Source(u64),
    Frame(Frame),
    Feedback(Vec<u8>),
}
struct Queued {
    item: Item,
    class: Class,
    bytes: usize,
    deadline: Instant,
}
struct Group {
    id: u64,
    shards: Vec<Vec<u8>>,
    opened: Instant,
}

pub struct Sender {
    budget: CacheBudget,
    compact: bool,
    repair: RepairConfig,
    next_sequence: u64,
    next_message: u64,
    group: Option<Group>,
    cache: BTreeMap<u64, Source>,
    control: VecDeque<Queued>,
    queue: VecDeque<Queued>,
    control_turn: bool,
    queued_bytes: usize,
    codecs: BTreeMap<(usize, usize), ReedSolomon>,
    shard_bytes: usize,
}

impl Default for Sender {
    fn default() -> Self {
        Self {
            budget: CacheBudget::default(),
            compact: false,
            repair: RepairConfig::default(),
            next_sequence: 1,
            next_message: 1,
            group: None,
            cache: BTreeMap::new(),
            control: VecDeque::new(),
            queue: VecDeque::new(),
            control_turn: true,
            queued_bytes: 0,
            codecs: BTreeMap::new(),
            shard_bytes: SHARD_BYTES,
        }
    }
}

impl Sender {
    pub fn new(repair: RepairConfig) -> Self {
        Self {
            repair,
            ..Self::default()
        }
    }
    pub(crate) fn share_cache_budget(&mut self, budget: CacheBudget) {
        assert!(self.cache.is_empty());
        self.budget = budget;
    }
    pub fn cached_global(&self) -> usize {
        self.budget.used()
    }
    pub fn cache_limit(&self, controller: &Controller) -> usize {
        // Retention capacity, NOT a congestion window or an unsent queue target.
        // Account at full source size; small-packet PPS retains a hard count cap.
        controller
            .retention_bytes()
            .div_ceil(self.shard_bytes + SOURCE_HEADER + WIRE_OVERHEAD)
            .clamp(MAX_QUEUE, MAX_SOURCES)
    }
    pub fn enable_compact(&mut self) {
        self.compact = true;
    }
    /// Policy revocation: drop payload, repair and retry state, preserving all
    /// sequence/message counters so a surviving epoch never reuses identifiers.
    pub fn discard_queued(&mut self) -> usize {
        let dropped = self.queue.len() + self.control.len();
        self.group = None;
        self.cache.clear();
        self.queue.clear();
        self.control.clear();
        self.queued_bytes = 0;
        dropped
    }
    pub fn set_datagram_limit(
        &mut self,
        limit: usize,
        controller: &Controller,
        now: Instant,
    ) -> Result<()> {
        ensure!(
            (MIN_UDP..=crate::transport::wire::MAX_UDP).contains(&limit),
            "datagram limit"
        );
        let size = limit - DATAGRAM_OVERHEAD - SOURCE_HEADER;
        if self.shard_bytes != size {
            // Finish this group at its original dimensions. Queued oversized
            // frames are discarded by poll after a shrink, never IP-fragmented.
            self.seal(controller, now)?;
            self.shard_bytes = size;
        }
        Ok(())
    }
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
    pub fn send_delay(&self, controller: &Controller, now: Instant) -> Option<Duration> {
        [self.control.front(), self.queue.front()]
            .into_iter()
            .flatten()
            .map(|q| {
                controller
                    .send_delay(q.class, q.bytes, now)
                    .min(q.deadline.saturating_duration_since(now))
            })
            .min()
    }
    pub fn queued_control_packets(&self) -> usize {
        self.control.len()
    }
    pub fn queued_data_packets(&self) -> usize {
        self.queue.len()
    }
    pub fn in_flight(&self) -> usize {
        self.cache.len()
    }
    /// A non-consuming preflight for ingress backpressure. Enqueue repeats the
    /// same checks; no permit, packet copy, counter, or FEC state is created here.
    pub fn can_enqueue(&self, bytes: usize, controller: &Controller) -> bool {
        if bytes == 0 || bytes > MAX_MESSAGE {
            return false;
        }
        let count = bytes.div_ceil(self.shard_bytes - FRAGMENT_HEADER);
        self.queue.len() + count * (MAX_M + 2) <= MAX_QUEUE
            && self.cache.len() + count <= self.cache_limit(controller)
            && self.budget.available(count)
    }
    pub fn ingress_ready(&self, bytes: usize, controller: &Controller) -> bool {
        if !self.can_enqueue(bytes, controller) {
            return false;
        }
        let count = bytes.div_ceil(self.shard_bytes - FRAGMENT_HEADER);
        let source_bytes = bytes + count * (FRAGMENT_HEADER + SOURCE_HEADER + WIRE_OVERHEAD);
        self.queued_bytes + source_bytes <= controller.admission_queue_bytes()
    }
    pub fn enqueue(
        &mut self,
        message: Message,
        controller: &Controller,
        now: Instant,
    ) -> Result<()> {
        ensure!(
            !message.payload.is_empty() && message.payload.len() <= MAX_MESSAGE,
            "link message size"
        );
        let fragment_bytes = self.shard_bytes - FRAGMENT_HEADER;
        let count = message.payload.len().div_ceil(fragment_bytes);
        // Reserve enough space for every possible parity + seal, atomically.
        ensure!(
            self.can_enqueue(message.payload.len(), controller),
            "link send queue full"
        );
        ensure!(
            self.next_sequence.checked_add(count as u64).is_some() && self.next_message < u64::MAX,
            "link counter exhausted; renew session"
        );
        let mut reservation = self
            .budget
            .reserve(count)
            .ok_or_else(|| anyhow::anyhow!("transport source cache full"))?;
        self.flush_expired(controller, now)?;
        let id = self.next_message;
        self.next_message += 1;
        for (index, payload) in message.payload.chunks(fragment_bytes).enumerate() {
            let seq = self.next_sequence;
            self.next_sequence += 1;
            let group = self.group.get_or_insert_with(|| Group {
                id: seq,
                shards: Vec::with_capacity(MAX_K),
                opened: now,
            });
            let group_id = group.id;
            let group_index = group.shards.len() as u8;
            let shard = Fragment {
                sequence: seq,
                message: id,
                index,
                count,
                kind: message.kind,
                payload,
            }
            .encode();
            let mut padded = Vec::with_capacity(self.shard_bytes);
            padded.extend_from_slice(&shard);
            // Keep actual lengths until the group closes. Reserving the proven
            // ceiling avoids reallocations if a later source is larger, but
            // short groups need not put an MTU's worth of zeroes on the wire.
            group.shards.push(padded);
            let compact = self.compact && count == 1;
            let bytes = shard.len() + SOURCE_HEADER + WIRE_OVERHEAD
                - if compact { SINGLE_SAVING } else { 0 };
            self.cache.insert(
                seq,
                Source {
                    _reservation: reservation.take_one(),
                    group: group_id,
                    index: group_index,
                    shard,
                    compact,
                    created: now,
                    first_sent: None,
                    last_sent: None,
                    stamps: [0; 3],
                    attempts: 0,
                    scheduled: true,
                    retry_after: now,
                },
            );
            self.push(Queued {
                item: Item::Source(seq),
                class: Class::Data,
                bytes,
                deadline: now + SOURCE_QUEUE_LIFETIME,
            });
            if self.group.as_ref().is_some_and(|g| g.shards.len() == MAX_K) {
                self.seal(controller, now)?;
            }
        }
        Ok(())
    }

    fn push(&mut self, item: Queued) {
        self.queued_bytes += item.bytes;
        self.queue.push_back(item);
    }
    pub fn control(&mut self, frame: Frame, now: Instant) -> bool {
        // Feedback is also subject to PMTU. Splitting preserves individual ACK
        // timestamps and prevents a small-MTU link from losing all feedback.
        if let Frame::Ack(acks) = &frame {
            let count = ((self.shard_bytes + SOURCE_HEADER - 2) / 25).min(MAX_FEEDBACK);
            if acks.len() > count {
                if self.control.len() + acks.len().div_ceil(count) > MAX_CONTROL_QUEUE {
                    return false;
                }
                return acks
                    .chunks(count)
                    .all(|part| self.control(Frame::Ack(part.to_vec()), now));
            }
        }
        if self.control.len() >= MAX_CONTROL_QUEUE {
            return false;
        }
        let encoded = if self.compact {
            frame.encode_compact_ack()
        } else {
            None
        }
        .unwrap_or_else(|| frame.encode());
        let bytes = encoded.len() + WIRE_OVERHEAD;
        self.queued_bytes += bytes;
        self.control.push_back(Queued {
            item: Item::Feedback(encoded),
            class: Class::Control,
            bytes,
            deadline: now + LIFETIME,
        });
        true
    }
    pub fn flush_expired(&mut self, controller: &Controller, now: Instant) -> Result<()> {
        if self
            .group
            .as_ref()
            .is_some_and(|g| now.saturating_duration_since(g.opened) >= GROUP_WAIT)
        {
            self.seal(controller, now)?;
        }
        Ok(())
    }
    fn seal(&mut self, controller: &Controller, now: Instant) -> Result<()> {
        let Some(mut group) = self.group.take() else {
            return Ok(());
        };
        let k = group.shards.len();
        let available = MAX_QUEUE.saturating_sub(self.queue.len());
        if available == 0 {
            return Ok(());
        }
        let m = if self.repair.fec {
            controller.parity_count(k).min(available - 1)
        } else {
            0
        };
        // Seal is ordered behind originals, with their earliest queue deadline.
        // A longer-lived seal can survive all its unsent originals and consume
        // the entire pacer under sustained overload, starving useful payload.
        let frame = Frame::Seal {
            group: group.id,
            k: k as u8,
            m: m as u8,
        };
        self.push(Queued {
            bytes: frame.encoded_len() + WIRE_OVERHEAD,
            item: Item::Frame(frame),
            class: Class::Data,
            deadline: group.opened + SOURCE_QUEUE_LIFETIME,
        });
        if m == 0 {
            return Ok(());
        }
        // GGB3 receivers already accept variable parity width, with this lower
        // bound. Pad to the longest source, not to unused path capacity. Source
        // bytes/identifiers, K/M, protection policy and recovery stay unchanged.
        let width = group
            .shards
            .iter()
            .map(Vec::len)
            .max()
            .expect("nonempty FEC group")
            .max(MIN_SHARD_BYTES);
        for shard in &mut group.shards {
            shard.resize(width, 0);
        }
        group.shards.extend((0..m).map(|_| vec![0; width]));
        let codec = self
            .codecs
            .entry((k, m))
            .or_insert_with(|| ReedSolomon::new(k, m).expect("bounded FEC dimensions"));
        codec.encode(&mut group.shards)?;
        for (index, shard) in group.shards.into_iter().skip(k).enumerate() {
            let frame = Frame::Parity {
                group: group.id,
                k: k as u8,
                m: m as u8,
                index: index as u8,
                shard,
            };
            self.push(Queued {
                bytes: frame.encoded_len() + WIRE_OVERHEAD,
                item: Item::Frame(frame),
                class: Class::Fec,
                deadline: now + Duration::from_millis(100),
            });
        }
        Ok(())
    }

    pub fn acknowledge(
        &mut self,
        ack: Ack,
        clock: &mut FeedbackClock,
        controller: &mut Controller,
        now: Instant,
        stats: &mut LinkStats,
    ) {
        let Some(source) = self.cache.get(&ack.sequence) else {
            return;
        };
        let Some(first_sent) = source.first_sent else {
            return;
        };
        if ack.arrival != Arrival::Recovered
            && !source.stamps[..usize::from(source.attempts)].contains(&ack.sent_us)
        {
            return;
        }
        let bytes = source.wire_bytes();
        let origin = if ack.arrival == Arrival::Original {
            first_sent
        } else {
            source.last_sent.unwrap_or(first_sent)
        };
        controller.feedback(
            bytes,
            ack.arrival,
            (ack.sent_us, ack.received_us),
            now.saturating_duration_since(origin),
            now,
            clock,
        );
        self.cache.remove(&ack.sequence);
        stats.acknowledged += 1;
        if ack.arrival == Arrival::Recovered {
            stats.peer_fec_recovered += 1;
        }
    }

    pub fn retransmit(&mut self, sequence: u64, now: Instant, rto: Duration) {
        if !self.repair.rtx {
            return;
        }
        let Some(source) = self.cache.get_mut(&sequence) else {
            return;
        };
        if source.scheduled
            || source.attempts >= 3
            || now.saturating_duration_since(source.created) >= LIFETIME
            || now < source.retry_after
        {
            return;
        }
        let Some(last_sent) = source.last_sent else {
            return;
        };
        // Repeated NACKs cannot cause a retransmission storm.
        if now.saturating_duration_since(last_sent) < rto.min(Duration::from_millis(10)) {
            return;
        }
        if self.queue.len() >= MAX_QUEUE {
            return;
        }
        source.scheduled = true;
        let age = now.saturating_duration_since(source.first_sent.unwrap_or(now));
        let class = if age <= rto {
            Class::EarlyRtx
        } else {
            Class::LateRtx
        };
        let bytes = source.wire_bytes();
        self.push(Queued {
            item: Item::Source(sequence),
            class,
            bytes,
            deadline: now + Duration::from_millis(100),
        });
    }

    pub fn maintain(
        &mut self,
        now: Instant,
        controller: &mut Controller,
        stats: &mut LinkStats,
    ) -> Result<()> {
        self.flush_expired(controller, now)?;
        let rto = controller.rto();
        // Sequence order is creation order (the owner's monotonic clock).
        // last_sent >= created: before even the oldest copy reaches RTO or
        // lifetime, no copy can need retry/expiry. Avoid walking an entire BDP
        // every millisecond. Lost/old copies still take the original full scan;
        // no deadline, retry budget, or FEC group timer is relaxed.
        if self.cache.first_key_value().is_none_or(|(_, source)| {
            now.saturating_duration_since(source.created) < rto.min(LIFETIME)
        }) {
            return Ok(());
        }
        stats.cache_scan_runs += 1;
        stats.cache_scan_sources += self.cache.len() as u64;
        let mut expired = vec![];
        let mut retry = vec![];
        for (&id, source) in &self.cache {
            if now.saturating_duration_since(source.created) >= LIFETIME {
                expired.push(id);
            } else if self.repair.rtx
                && source
                    .last_sent
                    .is_some_and(|at| now.saturating_duration_since(at) >= rto)
            {
                retry.push(id);
            }
        }
        for id in expired {
            if let Some(source) = self.cache.remove(&id) {
                if source.first_sent.is_some() {
                    controller.lost(source.wire_bytes(), now);
                }
                stats.expired_sources += 1;
            }
        }
        for id in retry {
            self.retransmit(id, now, rto);
        }
        Ok(())
    }

    pub fn poll(
        &mut self,
        now: Instant,
        sent_us: u64,
        controller: &mut Controller,
        stats: &mut LinkStats,
    ) -> Option<Vec<u8>> {
        // Hard work bound, even if ACKs have made every queued retry obsolete.
        for _ in 0..64 {
            let use_control = self.control.front().is_some_and(|q| {
                now >= q.deadline
                    || (controller.paced(q.class, q.bytes)
                        && (self.control_turn
                            || self
                                .queue
                                .front()
                                .is_none_or(|data| !controller.paced(data.class, data.bytes))))
            });
            let queue = if use_control {
                &mut self.control
            } else {
                &mut self.queue
            };
            let front = queue.front()?;
            let obsolete = matches!(front.item, Item::Source(id) if !self.cache.contains_key(&id));
            let oversized = front.bytes > self.shard_bytes + SOURCE_HEADER + WIRE_OVERHEAD;
            let expired = now >= front.deadline || oversized;
            let rejected =
                !controller.protection_allows(front.class, front.bytes, self.queued_bytes);
            if !obsolete && !expired && !rejected && !controller.paced(front.class, front.bytes) {
                return None;
            }
            let queued = queue.pop_front()?;
            self.queued_bytes -= queued.bytes;
            if obsolete {
                continue;
            }
            if expired || rejected {
                stats.queue_dropped += 1;
                if rejected {
                    controller.reject(queued.class);
                }
                if let Item::Source(id) = queued.item {
                    if queued.class == Class::Data || oversized {
                        if self
                            .cache
                            .remove(&id)
                            .is_some_and(|s| s.first_sent.is_none())
                        {
                            stats.unsent_sources_dropped += 1;
                        }
                    } else if let Some(source) = self.cache.get_mut(&id) {
                        source.scheduled = false;
                        // A budget/queue rejection did not send a packet. Do not
                        // re-enqueue the same overdue retry on every poll/NACK;
                        // wait one RTO, still bounded by the source lifetime.
                        source.retry_after = now + controller.rto();
                    }
                }
                continue;
            }
            // Queue residence is separate from path RTT and retained copies.
            let age_us = |lifetime| {
                now.saturating_duration_since(queued.deadline - lifetime)
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64
            };
            if queued.class == Class::Data && matches!(&queued.item, Item::Source(_)) {
                stats.max_data_queue_wait_us = stats
                    .max_data_queue_wait_us
                    .max(age_us(SOURCE_QUEUE_LIFETIME));
            } else if queued.class == Class::Control {
                stats.max_feedback_queue_wait_us =
                    stats.max_feedback_queue_wait_us.max(age_us(LIFETIME));
            }
            let encoded = match queued.item {
                Item::Source(id) => {
                    let source = self.cache.get_mut(&id)?;
                    let retransmitted = source.attempts > 0;
                    source.first_sent.get_or_insert(now);
                    source.last_sent = Some(now);
                    source.stamps[usize::from(source.attempts)] = sent_us;
                    source.attempts += 1;
                    source.scheduled = false;
                    if retransmitted {
                        stats.retransmitted += 1;
                    } else {
                        stats.original_sent += 1;
                    }
                    let encode = if source.compact {
                        Frame::encode_single_source
                    } else {
                        Frame::encode_source
                    };
                    encode(
                        source.group,
                        source.index,
                        sent_us,
                        retransmitted,
                        &source.shard,
                    )
                }
                Item::Frame(frame) => frame.encode(),
                Item::Feedback(bytes) => bytes,
            };
            controller.charge(queued.class, queued.bytes, now);
            // Share a replenished burst between feedback and payload. Strict
            // ACK priority can consume a small burst on every delayed tick,
            // expiring reverse originals despite ample average bandwidth.
            // An empty/unpaced queue never blocks the other, and all packets
            // still pay the same data, control and repair token budgets.
            self.control_turn = queued.class != Class::Control;
            stats.tx_wire_bytes += queued.bytes as u64;
            stats.tx_packets += 1;
            if queued.class == Class::Fec {
                stats.fec_sent += 1;
            }
            return Some(encoded);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_is_non_consuming_and_a_valid_ack_releases_shared_capacity() {
        let now = Instant::now();
        let budget = CacheBudget::default();
        let mut sender = Sender::default();
        sender.share_cache_budget(budget.clone());
        let mut controller = Controller::new(1_000_000_000, now);
        let mut stats = LinkStats::default();
        let mut clock = FeedbackClock::default();
        assert!(!sender.can_enqueue(0, &controller));
        assert!(!sender.can_enqueue(MAX_MESSAGE + 1, &controller));
        assert!(sender.can_enqueue(128, &controller));
        assert_eq!(budget.used(), 0);
        assert_eq!(sender.next_sequence, 1);
        sender
            .enqueue(
                Message {
                    kind: 1,
                    payload: vec![0; 128],
                },
                &controller,
                now,
            )
            .unwrap();
        // Occupy all other transport slots (another peer/epoch) without touching
        // this sender's per-path limit. Preflight and actual enqueue agree.
        let others = budget.reserve(32_767).unwrap();
        assert!(!sender.can_enqueue(128, &controller));
        assert!(
            sender
                .enqueue(
                    Message {
                        kind: 1,
                        payload: vec![0; 128]
                    },
                    &controller,
                    now
                )
                .is_err()
        );
        assert_eq!(sender.next_sequence, 2);
        assert_eq!(sender.in_flight(), 1);
        let original = sender.poll(now, 7, &mut controller, &mut stats).unwrap();
        assert!(matches!(
            Frame::decode(&original).unwrap(),
            Frame::Source { .. }
        ));
        let mut ack = Ack {
            sequence: 1,
            sent_us: 8,
            received_us: 1,
            arrival: Arrival::Original,
        };
        sender.acknowledge(
            ack,
            &mut clock,
            &mut controller,
            now + Duration::from_millis(100),
            &mut stats,
        );
        assert!(
            !sender.can_enqueue(128, &controller),
            "invalid timestamp must not release a slot"
        );
        ack.sent_us = 7;
        sender.acknowledge(
            ack,
            &mut clock,
            &mut controller,
            now + Duration::from_millis(100),
            &mut stats,
        );
        assert!(sender.can_enqueue(128, &controller));
        assert_eq!(budget.used(), 32_767);
        drop(others);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn paced_work_limit_stops_admission_before_packet_count_limit() {
        let now = Instant::now();
        let mut sender = Sender::default();
        let mut controller = Controller::new(1_000_000, now);
        while sender.ingress_ready(1200, &controller) {
            sender
                .enqueue(
                    Message {
                        kind: 1,
                        payload: vec![0; 1200],
                    },
                    &controller,
                    now,
                )
                .unwrap();
        }
        assert!(sender.queued_data_packets() < MAX_QUEUE / 2);
        assert!(sender.in_flight() < 2048);
        let count = sender.in_flight();
        assert!(!sender.ingress_ready(1200, &controller));
        assert_eq!(sender.in_flight(), count);
        let mut stats = LinkStats::default();
        for step in 1..=50 {
            let at = now + Duration::from_millis(step);
            controller.tick(at, sender.queued_bytes(), true);
            sender.poll(at, step * 1000, &mut controller, &mut stats);
        }
        assert!(
            sender.ingress_ready(1200, &controller),
            "pacer progress must reopen ingress"
        );
    }

    #[test]
    fn source_slots_have_a_bounded_payload_and_metadata_size() {
        // Conservative accounting envelope, excluding allocator bookkeeping.
        assert!(std::mem::size_of::<Source>() + SHARD_BYTES + 128 < 2048);
    }

    #[test]
    fn unsent_expiry_releases_shared_retention_reservation() {
        let now = Instant::now();
        let budget = CacheBudget::default();
        let mut sender = Sender::default();
        sender.share_cache_budget(budget.clone());
        let mut controller = Controller::new(64_000, now);
        let mut stats = LinkStats::default();
        sender
            .enqueue(
                Message {
                    kind: 1,
                    payload: vec![1; 1200],
                },
                &controller,
                now,
            )
            .unwrap();
        assert_eq!(budget.used(), 1);
        assert!(
            sender
                .poll(now + SOURCE_QUEUE_LIFETIME, 1, &mut controller, &mut stats)
                .is_none()
        );
        assert_eq!(stats.unsent_sources_dropped, 1);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn unused_timestamp_slots_do_not_authenticate_acknowledgements() {
        let now = Instant::now();
        let mut sender = Sender::default();
        let mut controller = Controller::new(10_000_000, now);
        let mut clock = FeedbackClock::default();
        let mut stats = LinkStats::default();
        sender
            .enqueue(
                Message {
                    kind: 2,
                    payload: vec![7; 100],
                },
                &controller,
                now,
            )
            .unwrap();
        let encoded = sender.poll(now, 123, &mut controller, &mut stats).unwrap();
        assert!(matches!(
            Frame::decode(&encoded).unwrap(),
            Frame::Source {
                sent_us: 123,
                retransmitted: false,
                ..
            }
        ));
        let mut ack = Ack {
            sequence: 1,
            sent_us: 0,
            received_us: 1000,
            arrival: Arrival::Original,
        };
        sender.acknowledge(ack, &mut clock, &mut controller, now, &mut stats);
        assert_eq!(sender.in_flight(), 1);
        assert_eq!(stats.acknowledged, 0);
        ack.sent_us = 123;
        sender.acknowledge(ack, &mut clock, &mut controller, now, &mut stats);
        assert_eq!(sender.in_flight(), 0);
        assert_eq!(stats.acknowledged, 1);
    }
}
