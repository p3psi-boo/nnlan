//! Bounded delay trend, using original packet timestamps from one key epoch.
//! Regress smoothed accumulated delay against receive time, not against delay.
//! See docs/transport-implementation.md for the reference and overlay choices.
use std::collections::VecDeque;

const WINDOW: usize = 20;
const GROUP_US: u64 = 5_000;
const IDLE_US: u64 = 1_000_000;

#[derive(Clone, Copy)]
struct Group {
    first_sent: u64,
    first_received: u64,
    sent: u64,
    received: u64,
}

pub(super) struct Delay {
    group: Option<Group>,
    origin: Option<(u64, u64)>,
    points: VecDeque<(f64, f64)>,
    smoothed: f64,
    count: u32,
    previous_sent: u64,
    updated_us: u64,
    overuse_ms: Option<f64>,
    overuse_count: u32,
    pub slope: f64,
    pub threshold: f64,
    pub overusing: bool,
}

impl Default for Delay {
    fn default() -> Self {
        Self {
            group: None,
            origin: None,
            points: VecDeque::with_capacity(WINDOW),
            smoothed: 0.0,
            count: 0,
            previous_sent: 0,
            updated_us: 0,
            overuse_ms: None,
            overuse_count: 0,
            slope: 0.0,
            threshold: 12.5,
            overusing: false,
        }
    }
}

impl Delay {
    /// Returns true only for a newly fitted full window. A burst contributes
    /// one observation, regardless of packet count or the ACK batching layout.
    pub fn observe(&mut self, sent: u64, received: u64) -> bool {
        let next = Group {
            first_sent: sent,
            first_received: received,
            sent,
            received,
        };
        let Some(group) = self.group.as_mut() else {
            self.group = Some(next);
            return false;
        };
        if sent < group.first_sent {
            return false;
        }
        if sent.saturating_sub(group.sent) > IDLE_US {
            *self = Self::default();
            self.group = Some(next);
            return false;
        }
        // A receiver draining a scheduling/network burst must not contribute
        // many samples at almost the same receive time. Coalesce compressed
        // arrivals, bounded to a 100 ms receive span, as well as send-time groups.
        let received_delta = i128::from(received) - i128::from(group.received);
        let send_delta = i128::from(sent) - i128::from(group.sent);
        let draining_burst = received_delta < send_delta
            && received_delta <= i128::from(GROUP_US)
            && received.saturating_sub(group.first_received) < 100_000;
        if sent - group.first_sent < GROUP_US || draining_burst {
            group.sent = group.sent.max(sent);
            group.received = group.received.max(received);
            return false;
        }
        let complete = *group;
        *group = next;
        self.fit(complete)
    }

    fn fit(&mut self, group: Group) -> bool {
        let (sent, received) = *self.origin.get_or_insert((group.sent, group.received));
        // Signed differences within each clock domain cancel the clock offset.
        // Keep negative arrival steps: clipping those would turn jitter into drift.
        let x = (i128::from(group.received) - i128::from(received)) as f64 / 1000.0;
        let raw = x - (group.sent - sent) as f64 / 1000.0;
        self.smoothed = self.smoothed * 0.9 + raw * 0.1;
        if self.points.len() == WINDOW {
            self.points.pop_front();
        }
        self.points.push_back((x, self.smoothed));
        self.count = (self.count + 1).min(60);
        let send_delta_ms = group.sent.saturating_sub(self.previous_sent) as f64 / 1000.0;
        self.previous_sent = group.sent;
        let elapsed_ms =
            group.received.saturating_sub(self.updated_us).min(100_000) as f64 / 1000.0;
        self.updated_us = self.updated_us.max(group.received);
        if self.points.len() < WINDOW {
            return false;
        }
        let mean_x = self.points.iter().map(|p| p.0).sum::<f64>() / WINDOW as f64;
        let mean_y = self.points.iter().map(|p| p.1).sum::<f64>() / WINDOW as f64;
        let variance = self
            .points
            .iter()
            .map(|p| (p.0 - mean_x).powi(2))
            .sum::<f64>();
        if variance <= f64::EPSILON {
            return false;
        }
        let covariance = self
            .points
            .iter()
            .map(|p| (p.0 - mean_x) * (p.1 - mean_y))
            .sum::<f64>();
        let slope = covariance / variance;
        let score = slope * f64::from(self.count) * 4.0;
        if score > self.threshold {
            self.overuse_ms = Some(
                self.overuse_ms
                    .map_or(send_delta_ms / 2.0, |ms| ms + send_delta_ms),
            );
            self.overuse_count = self.overuse_count.saturating_add(1);
            if self.overuse_ms.is_some_and(|ms| ms > 10.0)
                && self.overuse_count > 1
                && slope >= self.slope
            {
                self.overusing = true;
                self.overuse_ms = Some(0.0);
                self.overuse_count = 0;
            }
        } else {
            self.overusing = false;
            self.overuse_ms = None;
            self.overuse_count = 0;
        }
        self.slope = slope;
        let magnitude = score.abs();
        if magnitude <= self.threshold + 15.0 {
            let gain = if magnitude < self.threshold {
                0.039
            } else {
                0.0087
            };
            self.threshold = (self.threshold + gain * (magnitude - self.threshold) * elapsed_ms)
                .clamp(6.0, 600.0);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_receive_batches_do_not_manufacture_congestion() {
        for period_ms in [10, 20, 50, 100, 200] {
            let mut delay = Delay::default();
            let mut fits = 0;
            for sent_ms in 0_u64..30_000 {
                let received_ms = sent_ms.div_ceil(period_ms) * period_ms + 20;
                fits += usize::from(delay.observe(sent_ms * 1000, received_ms * 1000));
                assert!(
                    !delay.overusing,
                    "fixed receive batches: {period_ms} ms, at {sent_ms} ms"
                );
            }
            assert!(fits >= 100, "must estimate, not discard the evidence");
        }
        // Batch compression is not permission to ignore a genuinely growing queue.
        let mut delay = Delay::default();
        for sent_ms in 0_u64..3000 {
            delay.observe(sent_ms * 1000, (sent_ms.div_ceil(50) * 60 + 20) * 1000);
        }
        assert!(delay.overusing);
        assert!(delay.slope > 0.1);
    }

    #[test]
    fn sustained_growth_is_detected_and_draining_clears_it() {
        let mut delay = Delay::default();
        for n in 0..100 {
            delay.observe(n * 10_000, 900_000_000 + n * 12_000);
        }
        assert!(delay.overusing);
        assert!(delay.slope > 0.1);
        for n in 100..200 {
            delay.observe(n * 10_000, 900_400_000 + n * 8_000);
        }
        assert!(!delay.overusing);
        assert!(delay.slope < 0.0);
    }

    #[test]
    fn group_rate_memory_clock_offsets_reordering_and_idle_are_bounded() {
        let mut a = Delay::default();
        let mut b = Delay::default();
        let mut fits = 0;
        for n in 0..100_000 {
            let sent = n * 10;
            fits += usize::from(a.observe(sent, sent + 1000));
            b.observe(sent + 9_000_000_000, sent + 17_000_000_000);
            assert!(a.points.len() <= WINDOW);
        }
        assert!(fits > 100 && fits < 200);
        assert_eq!(a.slope, 0.0);
        assert_eq!(a.slope, b.slope);
        assert_eq!(a.threshold, b.threshold);
        let group = a.group.unwrap();
        assert!(!a.observe(1, u64::MAX));
        assert_eq!(a.group.unwrap().sent, group.sent);
        assert!(!a.observe(3_000_000, 4_000_000));
        assert!(a.points.is_empty());
        assert!(!a.overusing);
    }
}
