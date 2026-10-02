//! Bounded FEC/cache state for one authenticated key epoch.
//! The owner supplies one Controller for all epochs on the same adjacent path.
//! Originals are immediately schedulable; only parity waits for a group deadline.
mod cache;
pub(crate) use cache::CacheBudget;
mod controller;
mod delay;
pub mod frame;
mod receive;
mod send;

use crate::config::RepairConfig;
use crate::reliability::fec::FecScope;
use anyhow::Result;
use controller::FeedbackClock;
use frame::{Ack, Arrival, Fragment, Frame, WIRE_OVERHEAD};
use receive::Receiver;
use send::Sender;
use serde::Serialize;
use std::time::{Duration, Instant};

pub use controller::{ControlStats, Controller};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub kind: u8,
    pub payload: Vec<u8>,
}

#[derive(Default, Clone, Serialize)]
pub struct LinkStats {
    pub repair: RepairConfig,
    pub compact: bool,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_wire_bytes: u64,
    pub rx_wire_bytes: u64,
    pub original_sent: u64,
    pub fec_sent: u64,
    pub fec_recovered: u64,
    pub peer_fec_recovered: u64,
    pub retransmitted: u64,
    pub acknowledged: u64,
    pub expired_sources: u64,
    pub queue_dropped: u64,
    /// Admitted original sources discarded before their first transmission.
    /// Excludes rejected/expired repair frames and already-sent source expiry.
    pub unsent_sources_dropped: u64,
    pub queued_bytes: usize,
    pub queued_control_packets: usize,
    pub queued_data_packets: usize,
    pub in_flight: usize,
    pub source_cache_limit: usize,
    pub admission_queue_bytes: usize,
    pub transport_cached_sources: usize,
    pub cache_scan_runs: u64,
    pub cache_scan_sources: u64,
    pub max_data_queue_wait_us: u64,
    pub max_feedback_queue_wait_us: u64,
    pub control: ControlStats,
}

pub struct Link {
    scope: FecScope,
    origin: Instant,
    feedback_at: Instant,
    maintained_at: Option<Instant>,
    sender: Sender,
    receiver: Receiver,
    clock: FeedbackClock,
    stats: LinkStats,
}

impl Link {
    pub fn new(scope: FecScope, now: Instant, repair: RepairConfig) -> Self {
        Self {
            scope,
            origin: now,
            feedback_at: now,
            maintained_at: None,
            sender: Sender::new(repair),
            receiver: Receiver::default(),
            clock: FeedbackClock::default(),
            stats: LinkStats {
                repair,
                ..LinkStats::default()
            },
        }
    }
    pub(crate) fn share_cache_budget(&mut self, budget: CacheBudget) {
        self.sender.share_cache_budget(budget);
    }
    pub(crate) fn load(&self) -> (usize, bool) {
        (self.sender.queued_bytes(), self.sender.in_flight() > 0)
    }
    pub(crate) fn send_delay(&self, controller: &Controller, now: Instant) -> Option<Duration> {
        self.sender.send_delay(controller, now)
    }
    pub(crate) fn reset_clock(&mut self) {
        self.clock = FeedbackClock::default();
    }
    pub(crate) fn supports_compact(&self) -> bool {
        self.stats.compact
    }
    pub(crate) fn enable_compact(&mut self) {
        self.stats.compact = true;
        self.sender.enable_compact();
    }
    pub fn scope(&self) -> FecScope {
        self.scope
    }
    pub(crate) fn discard_queued(&mut self) {
        self.stats.queue_dropped += self.sender.discard_queued() as u64;
    }
    pub fn set_datagram_limit(
        &mut self,
        limit: usize,
        now: Instant,
        controller: &Controller,
    ) -> Result<()> {
        self.sender.set_datagram_limit(limit, controller, now)
    }
    pub(crate) fn can_enqueue(&self, bytes: usize, controller: &Controller) -> bool {
        self.sender.ingress_ready(bytes, controller)
    }
    pub fn enqueue(
        &mut self,
        message: Message,
        now: Instant,
        controller: &Controller,
    ) -> Result<()> {
        self.sender.enqueue(message, controller, now)
    }
    pub fn receive_authenticated(
        &mut self,
        bytes: &[u8],
        now: Instant,
        controller: &mut Controller,
    ) -> Result<Vec<Message>> {
        let frame = Frame::decode(bytes)?;
        let received_data = matches!(
            frame,
            Frame::Source { .. } | Frame::Parity { .. } | Frame::Seal { .. }
        );
        self.stats.rx_packets += 1;
        self.stats.rx_wire_bytes += (bytes.len() + WIRE_OVERHEAD) as u64;
        let result = match frame {
            Frame::Source {
                group,
                index,
                sent_us,
                retransmitted,
                shard,
            } => {
                let sequence = Fragment::decode(&shard)?.sequence;
                let arrival = if retransmitted {
                    Arrival::Retransmitted
                } else {
                    Arrival::Original
                };
                let ack = Ack {
                    sequence,
                    sent_us,
                    received_us: self.micros(now),
                    arrival,
                };
                self.receiver
                    .source(group, index, shard, ack, now, &mut self.stats)
            }
            Frame::Parity {
                group,
                k,
                m,
                index,
                shard,
            } => self
                .receiver
                .parity(group, k, m, Some((index, shard)), now, &mut self.stats),
            Frame::Seal { group, k, m } => {
                self.receiver
                    .parity(group, k, m, None, now, &mut self.stats)
            }
            Frame::Ack(acks) => {
                for ack in acks {
                    self.sender
                        .acknowledge(ack, &mut self.clock, controller, now, &mut self.stats);
                }
                Ok(vec![])
            }
            Frame::Nack(ids) => {
                for id in ids {
                    self.sender.retransmit(id, now, controller.rto());
                }
                Ok(vec![])
            }
        };
        if received_data && result.is_ok() {
            controller.received_data(bytes.len() + WIRE_OVERHEAD);
        }
        result
    }
    fn micros(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.origin)
            .as_micros()
            .min(u128::from(u64::MAX - 1)) as u64
    }

    /// Call at most a few milliseconds apart. Returned datagrams MUST each get a
    /// fresh AEAD transmission nonce, including retry frames of the same source.
    pub fn poll(
        &mut self,
        now: Instant,
        max_packets: usize,
        controller: &mut Controller,
    ) -> Result<Vec<Vec<u8>>> {
        self.prepare_poll(now, controller)?;
        let mut output = Vec::with_capacity(max_packets.min(64));
        for _ in 0..max_packets.min(64) {
            let Some(bytes) = self
                .sender
                .poll(now, self.micros(now), controller, &mut self.stats)
            else {
                break;
            };
            output.push(bytes);
        }
        Ok(output)
    }
    fn prepare_poll(&mut self, now: Instant, controller: &mut Controller) -> Result<()> {
        // Fast I/O-driven pumping must not rescan every cached source per packet.
        // Deadlines are checked again by Sender::poll before transmission.
        if self
            .maintained_at
            .is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_millis(1))
        {
            self.sender.maintain(now, controller, &mut self.stats)?;
            self.maintained_at = Some(now);
        }
        if now.saturating_duration_since(self.feedback_at) >= Duration::from_millis(2) {
            for frame in self.receiver.feedback(now) {
                if !self.sender.control(frame, now) {
                    self.stats.queue_dropped += 1;
                }
            }
            self.feedback_at = now;
        }
        Ok(())
    }
    pub(crate) fn poll_one(
        &mut self,
        now: Instant,
        controller: &mut Controller,
    ) -> Result<Option<Vec<u8>>> {
        self.prepare_poll(now, controller)?;
        Ok(self
            .sender
            .poll(now, self.micros(now), controller, &mut self.stats))
    }
    pub fn stats(&self, controller: &Controller) -> LinkStats {
        LinkStats {
            control: controller.stats.clone(),
            queued_bytes: self.sender.queued_bytes(),
            queued_control_packets: self.sender.queued_control_packets(),
            queued_data_packets: self.sender.queued_data_packets(),
            in_flight: self.sender.in_flight(),
            source_cache_limit: self.sender.cache_limit(controller),
            admission_queue_bytes: controller.admission_queue_bytes(),
            transport_cached_sources: self.sender.cached_global(),
            ..self.stats.clone()
        }
    }
}

#[cfg(test)]
mod tests;
