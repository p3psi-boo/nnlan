//! One feedback loop for data, FEC, RTX and pacing. The reference documents contain
//! inferred algorithms: these are explicit overlay choices, not wire-compatible WebRTC.
use super::delay::Delay;
use super::frame::{Arrival, MAX_M};
use crate::reliability::fec::{RESUME_HOLD, SUPPRESS_HOLD};
use serde::Serialize;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const PROTECTION_WINDOW: Duration = Duration::from_millis(500);
const FAST_WINDOW: Duration = Duration::from_millis(300);
const MIN_SAMPLE_SPAN: Duration = Duration::from_millis(200);
const MIN_SAMPLE_BYTES: u64 = 12_000;
const MIN_RATE: f64 = 64_000.0 / 8.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Data,
    Control,
    Fec,
    EarlyRtx,
    LateRtx,
}

#[derive(Default, Clone, Serialize)]
pub struct ControlStats {
    pub rate_bps: u64,
    pub rtt_us: u64,
    pub delay_gradient_us: f64,
    pub delay_trend: f64,
    pub delay_threshold: f64,
    pub delay_overusing: bool,
    pub loss_ratio: f64,
    pub burst_bytes: u64,
    /// Decision counters may overlap when several backoff signals coincide.
    pub delay_backoffs: u64,
    pub loss_backoffs: u64,
    pub stale_backoffs: u64,
    pub probe_events: u64,
    pub sample_bytes: u64,
    pub acknowledged_sample_bytes: u64,
    pub fec_suppressed: bool,
    pub protection_used_bytes: u64,
    pub rtx_debt_bytes: u64,
    pub fec_rejected: u64,
    pub early_rtx_rejected: u64,
    pub late_rtx_rejected: u64,
}

struct Sample {
    at: Instant,
    bytes: u64,
    lost_bytes: u64,
    acknowledged_bytes: u64,
}
struct Charge {
    opened: Instant,
    at: Instant,
    fec: u64,
    rtx: u64,
}

// Timestamps are relative to each key epoch on both hosts. Never fit delay
// across those clock domains, even though their wire budget belongs to one path.
#[derive(Default)]
pub(super) struct FeedbackClock {
    previous: Option<(u64, u64)>,
    gradient: f64,
    delay: Delay,
}

struct DelaySignal {
    slope: f64,
    threshold: f64,
    overusing: bool,
}
impl Default for DelaySignal {
    fn default() -> Self {
        Self {
            slope: 0.0,
            threshold: 12.5,
            overusing: false,
        }
    }
}

pub struct Controller {
    rate: f64,
    ceiling: f64,
    tokens: f64,
    control_tokens: f64,
    received_credit: f64,
    burst: f64,
    queued_bytes: usize,
    updated: Instant,
    adjusted: Instant,
    feedback_at: Instant,
    waiting_since: Option<Instant>,
    rtt: f64,
    gradient: f64,
    delay: DelaySignal,
    delay_at: Option<Instant>,
    gradient_fresh: bool,
    feedback_fresh: bool,
    samples: VecDeque<Sample>,
    charges: VecDeque<Charge>,
    suppress_since: Option<Instant>,
    resume_since: Option<Instant>,
    suppressed: bool,
    overload_since: Option<Instant>,
    pub stats: ControlStats,
}

impl Controller {
    pub fn new(max_bps: u64, now: Instant) -> Self {
        let ceiling = (max_bps as f64 / 8.0).max(MIN_RATE);
        let rate = (8_100_000.0_f64 / 8.0).min(ceiling);
        Self {
            rate,
            ceiling,
            tokens: 2400.0,
            control_tokens: 1200.0,
            received_credit: 0.0,
            burst: 2400.0,
            queued_bytes: 0,
            updated: now,
            adjusted: now,
            feedback_at: now,
            waiting_since: None,
            rtt: 100_000.0,
            gradient: 0.0,
            delay: DelaySignal::default(),
            delay_at: None,
            gradient_fresh: false,
            feedback_fresh: false,
            samples: VecDeque::new(),
            charges: VecDeque::new(),
            suppress_since: None,
            resume_since: None,
            suppressed: false,
            overload_since: None,
            stats: ControlStats {
                loss_ratio: 0.05,
                rate_bps: (rate * 8.0) as u64,
                ..Default::default()
            },
        }
    }

    pub(super) fn feedback(
        &mut self,
        bytes: usize,
        arrival: Arrival,
        stamps: (u64, u64),
        rtt: Duration,
        now: Instant,
        clock: &mut FeedbackClock,
    ) {
        let (sent_us, received_us) = stamps;
        self.feedback_at = now;
        self.feedback_fresh = true;
        if arrival != Arrival::Recovered {
            self.rtt = self.rtt * 0.875 + rtt.as_micros() as f64 * 0.125;
        }
        if arrival == Arrival::Original {
            if let Some((sent, received)) = clock.previous
                && sent_us > sent
            {
                // Clock offset cancels. NEVER subtract timestamps from different hosts.
                // Reordering can make the receiver delta negative. Discarding
                // that half of the observations biases jitter into congestion.
                let delta = (i128::from(received_us)
                    - i128::from(received)
                    - i128::from(sent_us - sent)) as f64;
                clock.gradient = clock.gradient * 0.9 + delta.clamp(-100_000.0, 100_000.0) * 0.1;
            }
            if clock.previous.is_none_or(|(sent, _)| sent_us > sent) {
                clock.previous = Some((sent_us, received_us));
            }
            // Only a fitted window can replace the path's congestion signal.
            // A new epoch's first packet must not clear existing overuse.
            self.gradient = clock.gradient;
            if clock.delay.observe(sent_us, received_us) {
                self.delay_at = Some(now);
                self.gradient_fresh = true;
                self.delay = DelaySignal {
                    slope: clock.delay.slope,
                    threshold: clock.delay.threshold,
                    overusing: clock.delay.overusing,
                };
            }
        }
        self.sample(bytes, arrival != Arrival::Original, true, now);
    }

    pub fn lost(&mut self, bytes: usize, now: Instant) {
        self.sample(bytes, true, false, now);
    }
    fn sample(&mut self, bytes: usize, lost: bool, acknowledged: bool, now: Instant) {
        // One aggregated sample per millisecond bounds feedback memory at high PPS.
        if let Some(last) = self.samples.back_mut()
            && now.saturating_duration_since(last.at) < Duration::from_millis(1)
        {
            last.bytes += bytes as u64;
            if acknowledged {
                last.acknowledged_bytes += bytes as u64;
            }
            if lost {
                last.lost_bytes += bytes as u64;
            }
            return;
        }
        if self.samples.len() == 4096 {
            self.samples.pop_front();
        }
        self.samples.push_back(Sample {
            at: now,
            bytes: bytes as u64,
            lost_bytes: if lost { bytes as u64 } else { 0 },
            acknowledged_bytes: if acknowledged { bytes as u64 } else { 0 },
        });
    }

    /// Feedback owes its existence to authenticated received data, not ACKs of
    /// its own ACKs. Bound that allowance by actual wire bytes, with no credit
    /// from incoming ACK/NACK frames and no accumulated idle windfall.
    pub fn received_data(&mut self, bytes: usize) {
        self.received_credit = (self.received_credit + bytes as f64 * 0.1).min(2400.0);
    }

    pub fn tick(&mut self, now: Instant, queued_bytes: usize, pending_sources: bool) {
        self.queued_bytes = queued_bytes;
        // A retired/idle epoch must not leave a permanent congestion signal.
        // Keep fresh evidence across rekeys, not an unbounded cached verdict.
        if self
            .delay_at
            .is_some_and(|at| now.saturating_duration_since(at) > Duration::from_secs(1))
        {
            self.delay = DelaySignal::default();
            self.delay_at = None;
            self.gradient_fresh = false;
        }
        // An idle link has no feedback obligation. Start a new timeout when
        // sources become pending, not at the last ACK before an idle period.
        if pending_sources {
            self.waiting_since.get_or_insert(now);
        } else {
            self.waiting_since = None;
        }
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        // Use the larger allowance, not their sum. This also serves ACK-only
        // receive epochs after crossed rekeys, whose outgoing data BWE has no
        // samples. Control still pays the ordinary total pacer below; receiving
        // fast traffic never raises the outgoing data rate or its burst cap.
        let allowance = (elapsed * self.rate * 0.1).max(self.received_credit);
        self.control_tokens = (self.control_tokens + allowance).min(2400.0);
        self.received_credit = 0.0;
        self.updated = now;
        while self
            .samples
            .front()
            .is_some_and(|s| now.saturating_duration_since(s.at) > FAST_WINDOW)
        {
            self.samples.pop_front();
        }
        while self
            .charges
            .front()
            .is_some_and(|s| now.saturating_duration_since(s.at) >= PROTECTION_WINDOW)
        {
            self.charges.pop_front();
        }
        let (bytes, acknowledged) = self.samples.iter().fold((0_u64, 0_u64), |(b, a), s| {
            (b + s.bytes, a + s.acknowledged_bytes)
        });
        let long_enough = self
            .samples
            .front()
            .is_some_and(|s| now.saturating_duration_since(s.at) >= MIN_SAMPLE_SPAN);
        let valid = bytes >= MIN_SAMPLE_BYTES && long_enough;
        // Keep the full 12 KB loss-estimate gate. Low-rate recovery must use a
        // smaller ACK-backed probe gate, or a 64 kbps link can never collect
        // 12 KB within 300 ms and is permanently stuck after a congestion cut.
        let probe_bytes = (self.rate * MIN_SAMPLE_SPAN.as_secs_f64() * 0.5)
            .clamp(1000.0, MIN_SAMPLE_BYTES as f64);
        let can_probe = long_enough && acknowledged as f64 >= probe_bytes;
        // A sparse heartbeat is not a delay trend. Only original arrivals carry
        // comparable send/receive deltas; loss, FEC and RTX do not add confidence.
        // Use the adaptive ACK threshold so a genuinely slow link can still back
        // off, rather than imposing the 12 KB loss-estimate floor on delay control.
        let originals: u64 = self.samples.iter().map(|s| s.bytes - s.lost_bytes).sum();
        let delay_valid = long_enough && originals as f64 >= probe_bytes;
        let queue_ms = queued_bytes as f64 / self.rate * 1000.0;
        if now.saturating_duration_since(self.adjusted) >= Duration::from_millis(100) {
            if valid {
                let lost: u64 = self.samples.iter().map(|s| s.lost_bytes).sum();
                self.stats.loss_ratio = lost as f64 / bytes as f64;
            }
            let feedback_stale =
                now.saturating_duration_since(self.feedback_at) > Duration::from_secs(1);
            // Random loss alone is not treated as congestion. Delay growth is.
            // A finite random-loss exemption: sustained heavy loss together with
            // local queue pressure eventually backs off, even without clear delay growth.
            if valid && self.stats.loss_ratio > 0.2 && queue_ms > 40.0 {
                self.overload_since.get_or_insert(now);
            } else {
                self.overload_since = None;
            }
            let persistent_overload = self
                .overload_since
                .is_some_and(|at| now.saturating_duration_since(at) >= PROTECTION_WINDOW);
            let delay_growth = delay_valid && self.gradient_fresh && self.delay.overusing;
            // ACKs are not acknowledged. An ACK-only queue must not trigger a
            // feedback timeout, otherwise sparse reverse data starves both sides.
            let stale_queue = feedback_stale
                && queued_bytes > 0
                && self
                    .waiting_since
                    .is_some_and(|at| now.saturating_duration_since(at) > Duration::from_secs(1));
            if delay_growth || persistent_overload || stale_queue {
                self.stats.delay_backoffs += u64::from(delay_growth);
                self.stats.loss_backoffs += u64::from(persistent_overload);
                self.stats.stale_backoffs += u64::from(stale_queue);
                self.rate = (self.rate * 0.85).max(MIN_RATE).min(self.ceiling);
                self.burst = (self.burst * 0.5).max(2400.0);
            } else if can_probe && self.feedback_fresh && !feedback_stale && !self.delay.overusing {
                self.stats.probe_events += 1;
                self.rate = (self.rate * 1.04 + 1000.0).min(self.ceiling);
                self.burst = (self.burst + 1200.0).min((self.rate * 0.005).clamp(2400.0, 64_000.0));
            }
            self.adjusted = now;
            self.gradient_fresh = false;
            self.feedback_fresh = false;
        }
        // Suppress FEC under sustained saturation, not merely because FEC hid loss.
        let pressure = queue_ms > 40.0 || (delay_valid && self.delay.overusing);
        if !self.suppressed {
            self.resume_since = None;
            if pressure {
                let since = self.suppress_since.get_or_insert(now);
                if now.saturating_duration_since(*since) >= SUPPRESS_HOLD {
                    self.suppressed = true;
                }
            } else {
                self.suppress_since = None;
            }
        } else if !pressure && queue_ms < 10.0 && (!delay_valid || !self.delay.overusing) {
            let since = self.resume_since.get_or_insert(now);
            if now.saturating_duration_since(*since) >= RESUME_HOLD {
                self.suppressed = false;
                self.suppress_since = None;
            }
        } else {
            self.resume_since = None;
        }
        let (fec, rtx) = self.used();
        self.stats.sample_bytes = bytes;
        self.stats.acknowledged_sample_bytes = acknowledged;
        self.stats.rate_bps = (self.rate * 8.0) as u64;
        self.stats.rtt_us = self.rtt as u64;
        self.stats.delay_gradient_us = self.gradient;
        self.stats.delay_trend = self.delay.slope;
        self.stats.delay_threshold = self.delay.threshold;
        self.stats.delay_overusing = self.delay.overusing;
        self.stats.burst_bytes = self.burst as u64;
        self.stats.fec_suppressed = self.suppressed;
        self.stats.protection_used_bytes = fec + rtx;
        self.stats.rtx_debt_bytes = rtx.saturating_sub((self.repair_cap() * 0.2) as u64);
    }

    fn repair_cap(&self) -> f64 {
        self.rate * PROTECTION_WINDOW.as_secs_f64() * 0.35
    }
    fn used(&self) -> (u64, u64) {
        self.charges
            .iter()
            .fold((0, 0), |(f, r), c| (f + c.fec, r + c.rtx))
    }
    pub fn parity_count(&self, k: usize) -> usize {
        if self.suppressed {
            return 0;
        }
        let loss = self.stats.loss_ratio.clamp(0.0, 0.35);
        ((k as f64 * (loss / (1.0 - loss) + 0.1)).ceil() as usize).clamp(1, MAX_M)
    }
    pub(super) fn retention_bytes(&self) -> usize {
        // Some headroom for delayed feedback, capped before conversion. This
        // changes storage admission only: pacer and protection budgets are intact.
        (self.rate * (self.rtt / 1_000_000.0 * 1.5 + 0.010).min(0.5)).min(32.0 * 1024.0 * 1024.0)
            as usize
    }
    pub(super) fn admission_queue_bytes(&self) -> usize {
        // Five milliseconds of paced work, with a one-message floor and a
        // fixed ceiling. Retained (already sent) copies do not consume this.
        (self.rate * 0.005).clamp(48_000.0, 256_000.0) as usize
    }
    pub fn rto(&self) -> Duration {
        Duration::from_micros((self.rtt * 1.5 + 10_000.0).clamp(30_000.0, 500_000.0) as u64)
    }
    pub fn queue_delay(&self, bytes: usize) -> Duration {
        Duration::from_secs_f64(bytes as f64 / self.rate)
    }

    pub fn protection_allows(&self, class: Class, bytes: usize, queue_bytes: usize) -> bool {
        let (fec, rtx) = self.used();
        let cap = self.repair_cap();
        match class {
            Class::Fec => {
                !self.suppressed
                    && (fec + bytes as u64) as f64 <= cap * 0.8
                    && (fec + rtx + bytes as u64) as f64 <= cap
            }
            Class::EarlyRtx => (fec + rtx + bytes as u64) as f64 <= cap,
            Class::LateRtx => {
                (fec + rtx + bytes as u64) as f64 <= cap
                    && rtx as f64 <= cap * 0.2
                    && self.queue_delay(queue_bytes.max(self.queued_bytes))
                        < Duration::from_millis(40)
            }
            _ => true,
        }
    }
    pub fn reject(&mut self, class: Class) {
        match class {
            Class::Fec => self.stats.fec_rejected += 1,
            Class::EarlyRtx => self.stats.early_rtx_rejected += 1,
            Class::LateRtx => self.stats.late_rtx_rejected += 1,
            _ => (),
        }
    }
    pub fn paced(&self, class: Class, bytes: usize) -> bool {
        self.tokens >= bytes as f64
            && (class != Class::Control || self.control_tokens >= bytes as f64)
    }
    /// Forecast only; the ordinary tick/charge path remains the sole token owner.
    pub(super) fn send_delay(&self, class: Class, bytes: usize, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        let tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        let mut delay = ((bytes as f64 - tokens) / self.rate).max(0.0);
        if class == Class::Control {
            let allowance = (elapsed * self.rate * 0.1).max(self.received_credit);
            let control = (self.control_tokens + allowance).min(2400.0);
            delay = delay.max(((bytes as f64 - control) / (self.rate * 0.1)).max(0.0));
        }
        Duration::from_secs_f64(delay)
    }
    pub fn charge(&mut self, class: Class, bytes: usize, now: Instant) {
        self.tokens -= bytes as f64;
        if class == Class::Control {
            self.control_tokens -= bytes as f64;
        }
        let fec = if class == Class::Fec { bytes as u64 } else { 0 };
        let rtx = if matches!(class, Class::EarlyRtx | Class::LateRtx) {
            bytes as u64
        } else {
            0
        };
        if fec + rtx == 0 {
            return;
        }
        // Round time forward to 10 ms buckets; credit is never refunded early.
        if let Some(last) = self.charges.back_mut()
            && now.saturating_duration_since(last.opened) < Duration::from_millis(10)
        {
            last.fec += fec;
            last.rtx += rtx;
            last.at = now;
        } else {
            self.charges.push_back(Charge {
                opened: now,
                at: now,
                fec,
                rtx,
            });
        }
        self.stats.protection_used_bytes += fec + rtx;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn large_retention_cache_does_not_enlarge_unsent_queue_and_releases_on_revoke() {
        use super::super::{LinkStats, Message, cache::CacheBudget, send::Sender};
        let origin = Instant::now();
        let budget = CacheBudget::default();
        let mut sender = Sender::default();
        sender.share_cache_budget(budget.clone());
        let mut controller = Controller::new(1_000_000_000, origin);
        controller.rate = 125_000_000.0;
        controller.burst = 64_000.0; // Learned high-rate path, not the cold-start burst.
        controller.rtt = 100_000.0;
        let mut stats = LinkStats::default();
        let limit = sender.cache_limit(&controller);
        for index in 0..limit as u64 {
            let now = origin + Duration::from_micros(index * 50);
            controller.tick(now, sender.queued_bytes(), sender.in_flight() > 0);
            sender
                .enqueue(
                    Message {
                        kind: 1,
                        payload: vec![1; 1280],
                    },
                    &controller,
                    now,
                )
                .unwrap();
            for _ in 0..8 {
                if sender
                    .poll(now, index * 50 + 1, &mut controller, &mut stats)
                    .is_none()
                {
                    break;
                }
            }
            assert!(sender.queued_data_packets() < 16);
        }
        assert_eq!(sender.in_flight(), limit);
        assert_eq!(budget.used(), limit);
        let now = origin + Duration::from_millis(820);
        assert!(
            sender
                .enqueue(
                    Message {
                        kind: 1,
                        payload: vec![1; 1280]
                    },
                    &controller,
                    now
                )
                .is_err()
        );
        assert_eq!(
            budget.used(),
            limit,
            "failed admission must not reserve slots"
        );
        // A rate/RTT reduction closes admission; it never evicts already-sent
        // repair copies or manufactures credit in the shared pool.
        controller.rate = 64_000.0 / 8.0;
        assert_eq!(sender.cache_limit(&controller), 2048);
        assert!(!sender.can_enqueue(128, &controller));
        assert_eq!(sender.in_flight(), limit);
        assert_eq!(budget.used(), limit);
        sender.discard_queued();
        assert_eq!(budget.used(), 0, "revocation releases all retained payload");
        // Unsent queue still rejects well before the enlarged retention limit.
        let mut admitted = 0;
        while sender
            .enqueue(
                Message {
                    kind: 1,
                    payload: vec![1; 1280],
                },
                &controller,
                now,
            )
            .is_ok()
        {
            admitted += 1;
        }
        assert!(admitted < 2048);
        assert!(sender.queued_data_packets() <= 2048);
        drop(sender);
        assert_eq!(budget.used(), 0, "epoch retirement releases pending copies");
    }

    #[test]
    fn retention_capacity_tracks_bdp_without_increasing_send_queue_or_pacer() {
        use super::super::send::Sender;
        let now = Instant::now();
        let sender = Sender::default();
        let mut control = Controller::new(1_000_000_000, now);
        assert_eq!(sender.cache_limit(&control), 2048);
        control.rate = 125_000_000.0;
        control.rtt = 1_000.0;
        assert_eq!(sender.cache_limit(&control), 2048);
        let tokens = control.tokens;
        control.rtt = 20_000.0;
        assert!(sender.cache_limit(&control) > 2048);
        control.rtt = 100_000.0;
        assert!(sender.cache_limit(&control) > 8192);
        control.rtt = 10_000_000.0;
        assert_eq!(sender.cache_limit(&control), 16_384);
        assert_eq!(control.tokens, tokens);
        assert_eq!(control.burst, 2400.0);
        assert_eq!(super::super::send::MAX_QUEUE, 2048);
        control.rate = 64_000.0 / 8.0;
        assert_eq!(sender.cache_limit(&control), 2048);
    }

    #[test]
    fn send_forecast_obeys_data_and_control_tokens_without_spending_them() {
        let now = Instant::now();
        for class in [
            Class::Data,
            Class::Control,
            Class::Fec,
            Class::EarlyRtx,
            Class::LateRtx,
        ] {
            let mut controller = Controller::new(10_000_000, now);
            controller.tokens = 0.0;
            controller.control_tokens = 0.0;
            let delay = controller.send_delay(class, 1232, now);
            assert!(delay >= Duration::from_millis(1));
            assert_eq!(controller.tokens, 0.0);
            assert_eq!(controller.control_tokens, 0.0);
            controller.tick(now + delay + Duration::from_nanos(1), 0, false);
            assert!(controller.paced(class, 1232));
        }
        let mut controller = Controller::new(10_000_000, now);
        controller.control_tokens = 0.0;
        assert!(!controller.send_delay(Class::Control, 1000, now).is_zero());
        controller.received_data(10_000);
        assert!(controller.send_delay(Class::Control, 1000, now).is_zero());
    }

    use super::*;

    #[test]
    fn interleaved_key_clocks_never_manufacture_cross_epoch_delay() {
        let now = Instant::now();
        let mut c = Controller::new(100_000_000, now);
        let mut clocks = [FeedbackClock::default(), FeedbackClock::default()];
        for n in 0..100 {
            let at = now + Duration::from_millis(n * 10);
            for (index, clock) in clocks.iter_mut().enumerate() {
                let (sent_base, received_base) = if index == 0 {
                    (120_000_000, 9_000_000_000)
                } else {
                    (0, 700_000)
                };
                c.feedback(
                    1200,
                    Arrival::Original,
                    (sent_base + n * 10_000, received_base + n * 10_000),
                    Duration::from_millis(20),
                    at,
                    clock,
                );
            }
            c.tick(at, 1000, true);
        }
        assert_eq!(c.stats.delay_backoffs, 0);
        assert_eq!(c.stats.delay_gradient_us, 0.0);
        assert_eq!(c.stats.delay_trend, 0.0);
        assert!(c.stats.rate_bps > 8_100_000);
        assert!(clocks[0].previous.unwrap().0 > clocks[1].previous.unwrap().0);
    }

    #[test]
    fn new_clock_does_not_clear_fresh_congestion_but_stale_verdict_expires() {
        let now = Instant::now();
        let mut c = Controller::new(10_000_000, now);
        let mut old = FeedbackClock::default();
        for n in 0..100 {
            c.feedback(
                1200,
                Arrival::Original,
                (n * 10_000, n * 12_000),
                Duration::from_millis(20),
                now,
                &mut old,
            );
        }
        assert!(c.delay.overusing);
        let mut new = FeedbackClock::default();
        c.feedback(
            1200,
            Arrival::Original,
            (0, 900_000_000),
            Duration::from_millis(20),
            now,
            &mut new,
        );
        assert!(
            c.delay.overusing,
            "one new-epoch packet is not proof of a drained path"
        );
        c.tick(now + Duration::from_secs(2), 0, false);
        assert!(!c.delay.overusing, "retired epoch evidence must expire");
    }

    #[test]
    fn receive_credit_is_bounded_and_does_not_raise_the_total_pacer() {
        let now = Instant::now();
        let mut c = Controller::new(8_100_000, now);
        c.tokens = 0.0;
        c.control_tokens = 0.0;
        c.received_data(usize::MAX);
        assert_eq!(c.received_credit, 2400.0);
        c.tick(now, 0, false);
        assert_eq!(c.received_credit, 0.0);
        assert_eq!(c.control_tokens, 2400.0);
        assert!(!c.paced(Class::Control, 1200));
        c.tick(now + Duration::from_millis(2), 0, false);
        assert!(c.paced(Class::Control, 1200));
        c.charge(Class::Control, 1200, now + Duration::from_millis(2));
        assert!(!c.paced(Class::Control, 1200));
        assert_eq!(c.rate, 8_100_000.0 / 8.0);
        assert_eq!(c.burst, 2400.0);
    }

    #[test]
    fn receive_and_send_allowances_do_not_add_or_recur_without_new_data() {
        let now = Instant::now();
        let mut c = Controller::new(8_100_000, now);
        c.control_tokens = 0.0;
        c.received_data(1000);
        c.tick(now + Duration::from_millis(1), 0, false);
        assert_eq!(c.control_tokens, 101.25); // max(100, 101.25), not their sum
        c.control_tokens = 0.0;
        c.received_data(10_000);
        c.tick(now + Duration::from_millis(2), 0, false);
        assert_eq!(c.control_tokens, 1000.0);
        c.control_tokens = 0.0;
        c.tick(now + Duration::from_millis(3), 0, false);
        assert_eq!(c.control_tokens, 101.25);
        c.tick(now + Duration::from_secs(100), 0, false);
        assert_eq!(c.control_tokens, 2400.0);
    }

    #[test]
    fn isolated_receive_stall_is_not_sustained_queue_growth() {
        let now = Instant::now();
        let mut clock = FeedbackClock::default();
        let mut c = Controller::new(8_100_000, now);
        // One receive scheduling stall after a stable flow. Keep the same
        // evidence volume throughout; this must not pass by failing the gate.
        for n in 0..=200 {
            let sent = n * 10_000;
            let received = if (100..=110).contains(&n) {
                1_120_000
            } else {
                sent + 20_000
            };
            c.feedback(
                1200,
                Arrival::Original,
                (sent, received),
                Duration::from_micros(received + 20_000 - sent),
                now + Duration::from_micros(received + 20_000),
                &mut clock,
            );
            c.tick(now + Duration::from_micros(received + 20_000), 0, true);
        }
        assert_eq!(c.stats.delay_backoffs, 0);
    }

    #[test]
    fn reordered_arrivals_contribute_negative_delay_steps() {
        let now = Instant::now();
        let mut clock = FeedbackClock::default();
        let mut c = Controller::new(10_000_000, now);
        c.feedback(
            1000,
            Arrival::Original,
            (1000, 30_000),
            Duration::from_millis(30),
            now,
            &mut clock,
        );
        c.feedback(
            1000,
            Arrival::Original,
            (2000, 10_000),
            Duration::from_millis(10),
            now,
            &mut clock,
        );
        assert_eq!(c.gradient, -2100.0);
        // An old send timestamp must not replace the forward baseline.
        c.feedback(
            1000,
            Arrival::Original,
            (1500, 90_000),
            Duration::from_millis(30),
            now,
            &mut clock,
        );
        assert_eq!(c.gradient, -2100.0);
        assert_eq!(clock.previous, Some((2000, 10_000)));
    }

    #[test]
    fn cached_gradient_is_not_reapplied_without_new_evidence() {
        let now = Instant::now();
        let mut clock = FeedbackClock::default();
        let mut c = Controller::new(10_000_000, now);
        for n in 0..=30 {
            let received = 20_000 + n * 15_000;
            let at = now + Duration::from_micros(received);
            c.feedback(
                1200,
                Arrival::Original,
                (n * 10_000, received),
                Duration::from_micros(received - n * 10_000),
                at,
                &mut clock,
            );
            c.tick(at, 0, true);
        }
        // Consume the final feedback at the next controller decision boundary.
        c.tick(now + Duration::from_millis(600), 0, true);
        let reduced = c.rate;
        assert!(reduced < 8_100_000.0 / 8.0);
        for n in 7..=15 {
            c.tick(now + Duration::from_millis(n * 100), 0, true);
            assert_eq!(c.rate, reduced);
        }
        c.tick(now + Duration::from_millis(1600), 10_000, true);
        assert!(
            c.rate < reduced,
            "feedback timeout still backs off queued traffic"
        );
    }

    #[test]
    fn sparse_or_repaired_feedback_is_not_an_original_delay_trend() {
        let now = Instant::now();
        for arrival in [
            Arrival::Original,
            Arrival::Recovered,
            Arrival::Retransmitted,
        ] {
            let mut clock = FeedbackClock::default();
            let mut c = Controller::new(10_000_000, now);
            for n in 0..=30 {
                let at = now + Duration::from_millis(n * 100);
                c.feedback(
                    if arrival == Arrival::Original {
                        1
                    } else {
                        12_000
                    },
                    arrival,
                    (n * 100_000, n * 110_000),
                    Duration::from_millis(20),
                    at,
                    &mut clock,
                );
                // Even a fresh positive gradient is not sufficient without
                // enough original ACKs. Repairs must not manufacture confidence.
                c.gradient = 10_000.0;
                c.gradient_fresh = true;
                c.tick(at, 0, true);
            }
            assert_eq!(c.stats.delay_backoffs, 0);
            assert!(!c.stats.fec_suppressed);
        }
    }

    #[test]
    fn low_rate_original_delay_trend_still_backs_off() {
        let now = Instant::now();
        let mut clock = FeedbackClock::default();
        let mut c = Controller::new(128_000, now);
        // Fill the twenty-group window, including a real low-rate trend.
        for n in 0..=40 {
            let at = now + Duration::from_millis(n * 60 + 20);
            c.feedback(
                400,
                Arrival::Original,
                (n * 50_000, n * 60_000 + 20_000),
                Duration::from_millis(n * 10 + 20),
                at,
                &mut clock,
            );
            c.tick(at, 0, true);
        }
        assert!(c.stats.delay_backoffs > 0);
        assert!(c.stats.rate_bps < 128_000);
        assert_eq!(c.stats.loss_ratio, 0.05, "loss gate remains 12 KB");
    }

    #[test]
    fn ack_only_queues_do_not_need_feedback_but_still_have_a_budget() {
        let now = Instant::now();
        let mut c = Controller::new(10_000_000, now);
        for second in 1..=10 {
            let at = now + Duration::from_secs(second);
            c.tick(at, 1000, false);
            assert!(c.paced(Class::Control, 2400));
            c.charge(Class::Control, 2400, at);
            assert!(!c.paced(Class::Control, 1));
        }
        assert_eq!(c.stats.stale_backoffs, 0);
        assert_eq!(c.stats.rate_bps, 8_100_000);
        c.tick(now + Duration::from_secs(11), 1000, true);
        assert_eq!(
            c.stats.stale_backoffs, 0,
            "new data after idle gets a fresh timeout"
        );
        c.tick(now + Duration::from_millis(12_100), 1000, true);
        assert_eq!(c.stats.stale_backoffs, 1);
        assert!(
            c.stats.rate_bps < 8_100_000,
            "unacknowledged data still backs off"
        );
    }

    #[test]
    fn low_rate_acknowledgments_allow_recovery_but_expirations_do_not() {
        let now = Instant::now();
        let mut clock = FeedbackClock::default();
        let mut delivered = Controller::new(10_000_000, now);
        let mut lost = Controller::new(10_000_000, now);
        delivered.rate = MIN_RATE;
        lost.rate = MIN_RATE;
        for n in 0..=40 {
            let at = now + Duration::from_millis(n * 50);
            delivered.feedback(
                400,
                Arrival::Original,
                (n * 50_000, 900_000 + n * 50_000),
                Duration::from_millis(10),
                at,
                &mut clock,
            );
            lost.lost(400, at);
            delivered.tick(at, 0, true);
            lost.tick(at, 0, true);
        }
        assert!(delivered.rate > MIN_RATE * 1.5);
        assert_eq!(lost.rate, MIN_RATE);
        assert_eq!(
            delivered.stats.loss_ratio, 0.05,
            "12 KB loss gate remains intact"
        );
        let rate = delivered.rate;
        for n in 41..=60 {
            delivered.tick(now + Duration::from_millis(n * 50), 0, true);
        }
        assert_eq!(delivered.rate, rate, "no blind growth without fresh ACKs");
    }

    #[test]
    fn high_pps_mixed_loss_keeps_a_valid_time_window() {
        let now = Instant::now();
        let mut c = Controller::new(1_000_000_000, now);
        for ms in 0..=250 {
            for slot in 0..100 {
                c.sample(
                    1000,
                    slot % 2 == 0,
                    true,
                    now + Duration::from_micros(ms * 1000 + slot * 10),
                );
            }
        }
        assert!(c.samples.len() <= 251);
        c.tick(now + Duration::from_millis(251), 0, true);
        assert_eq!(c.stats.loss_ratio, 0.5);
    }
    #[test]
    fn repair_shared_cap_and_early_debt_are_real() {
        let now = Instant::now();
        let mut c = Controller::new(64_000, now);
        assert!(c.protection_allows(Class::Fec, 1000, 0));
        c.charge(Class::Fec, 1000, now);
        assert!(!c.protection_allows(Class::EarlyRtx, 401, 0));
        assert!(c.protection_allows(Class::EarlyRtx, 400, 0));
        c.charge(Class::EarlyRtx, 400, now);
        c.tick(now + Duration::from_millis(100), 0, true);
        assert_eq!(c.stats.protection_used_bytes, 1400);
        assert_eq!(c.stats.rtx_debt_bytes, 120);
        assert!(!c.protection_allows(Class::LateRtx, 1, 0));
        c.tick(now + PROTECTION_WINDOW, 0, true);
        assert!(c.protection_allows(Class::EarlyRtx, 1400, 0));
    }
    #[test]
    fn timestamps_with_different_origins_do_not_corrupt_delay_gradient() {
        let now = Instant::now();
        let mut clock = FeedbackClock::default();
        let mut c = Controller::new(8_100_000, now);
        for n in 0..30 {
            let t = now + Duration::from_millis(n * 10);
            c.feedback(
                1000,
                Arrival::Original,
                (n * 10_000, 900_000_000 + n * 10_000),
                Duration::from_millis(20),
                t,
                &mut clock,
            );
            c.tick(t, 0, true);
        }
        assert_eq!(c.stats.delay_gradient_us, 0.0);
        assert_eq!(c.stats.loss_ratio, 0.0);
    }
    #[test]
    fn suppression_and_resume_have_hysteresis() {
        let now = Instant::now();
        let mut c = Controller::new(64_000, now);
        c.tick(now, 100_000, true);
        c.tick(now + SUPPRESS_HOLD, 100_000, true);
        assert_eq!(c.parity_count(8), 0);
        c.tick(now + SUPPRESS_HOLD + Duration::from_millis(1), 0, true);
        c.tick(now + SUPPRESS_HOLD + RESUME_HOLD, 0, true);
        assert_eq!(c.parity_count(8), 0);
        c.tick(
            now + SUPPRESS_HOLD + RESUME_HOLD + Duration::from_millis(1),
            0,
            true,
        );
        assert!(c.parity_count(8) > 0);
    }
}
