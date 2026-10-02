//! Group boundary accounting only. No source-packet buffering or codec here.
use crate::identity::NodeId;
use anyhow::{Result, ensure};
use std::time::{Duration, Instant};

// Document-derived profile values, not proof of a completed controller.
// See docs/transport-implementation.md for profile provenance and active limits.
pub const DOCUMENTED_MAX_K: u16 = 109;
pub const SUPPRESS_HOLD: Duration = Duration::from_millis(2000);
pub const RESUME_HOLD: Duration = Duration::from_millis(5000);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FecScope {
    pub peer: NodeId,
    pub path_epoch: u64,
    pub key_epoch: u64,
    /// Sender's direction identifier. Never mix the opposite direction's sources.
    pub direction: u8,
}

pub struct FecBatch {
    scope: FecScope,
    count: u16,
    max_sources: u16,
    opened: Instant,
    max_wait: Duration,
}

impl FecBatch {
    pub fn new(
        scope: FecScope,
        max_sources: u16,
        max_wait: Duration,
        now: Instant,
    ) -> Result<Self> {
        ensure!(
            (1..=DOCUMENTED_MAX_K).contains(&max_sources),
            "invalid FEC source count"
        );
        ensure!(
            !max_wait.is_zero(),
            "FEC grouping deadline must be positive"
        );
        Ok(Self {
            scope,
            count: 0,
            max_sources,
            opened: now,
            max_wait,
        })
    }

    /// Account for an already independently schedulable original packet.
    /// Flush and create a new group before crossing any scope or deadline boundary.
    pub fn record_source(&mut self, scope: FecScope, now: Instant) -> Result<()> {
        ensure!(
            scope == self.scope,
            "FEC peer/path/key/direction changed; close the group first"
        );
        ensure!(now >= self.opened, "FEC clock moved backwards");
        ensure!(!self.should_flush(now), "FEC group is full or expired");
        self.count += 1;
        Ok(())
    }

    pub fn should_flush(&self, now: Instant) -> bool {
        self.count >= self.max_sources
            || now.saturating_duration_since(self.opened) >= self.max_wait
    }

    pub fn source_count(&self) -> u16 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn sparse_groups_close_on_deadline_and_epochs_stay_separate() {
        let now = Instant::now();
        let scope = FecScope {
            peer: test_id(1),
            path_epoch: 1,
            key_epoch: 1,
            direction: 0,
        };
        let mut group = FecBatch::new(scope, 109, Duration::from_millis(2), now).unwrap();
        group.record_source(scope, now).unwrap();
        assert!(!group.should_flush(now));
        assert!(group.should_flush(now + Duration::from_millis(2)));
        assert!(
            group
                .record_source(scope, now + Duration::from_millis(2))
                .is_err()
        );
        for other in [
            FecScope {
                path_epoch: 2,
                ..scope
            },
            FecScope {
                key_epoch: 2,
                ..scope
            },
            FecScope {
                peer: test_id(2),
                ..scope
            },
            FecScope {
                direction: 1,
                ..scope
            },
        ] {
            assert!(group.record_source(other, now).is_err());
        }
        assert_eq!(group.source_count(), 1);
    }

    #[test]
    fn full_groups_close_without_waiting_for_timer() {
        let now = Instant::now();
        let scope = FecScope {
            peer: test_id(1),
            path_epoch: 0,
            key_epoch: 0,
            direction: 0,
        };
        let mut g = FecBatch::new(scope, 1, Duration::from_secs(1), now).unwrap();
        g.record_source(scope, now).unwrap();
        assert!(g.should_flush(now));
        assert!(g.record_source(scope, now).is_err());
    }
}
