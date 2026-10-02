//! A transport-wide bound for retained source copies, shared across peers and keys.
//! Slots are reserved atomically per message; every removal path releases by Drop.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub(super) const MAX_SOURCES: usize = 16_384;
const GLOBAL_SOURCES: usize = 32_768;

#[derive(Clone, Default)]
pub(crate) struct CacheBudget(Arc<AtomicUsize>);

impl CacheBudget {
    pub(super) fn reserve(&self, count: usize) -> Option<Reservation> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(count)
                    .filter(|&next| next <= GLOBAL_SOURCES)
            })
            .ok()?;
        Some(Reservation {
            budget: self.clone(),
            count,
        })
    }
    pub(super) fn available(&self, count: usize) -> bool {
        self.used()
            .checked_add(count)
            .is_some_and(|n| n <= GLOBAL_SOURCES)
    }
    pub(super) fn used(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

pub(super) struct Reservation {
    budget: CacheBudget,
    count: usize,
}
impl Reservation {
    pub(super) fn take_one(&mut self) -> Self {
        assert!(self.count > 0);
        self.count -= 1;
        Self {
            budget: self.budget.clone(),
            count: 1,
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.count != 0 {
            self.budget.0.fetch_sub(self.count, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservations_are_atomic_and_release_partial_messages_and_epochs() {
        let budget = CacheBudget::default();
        let other_epoch = budget.clone();
        let mut batch = budget.reserve(GLOBAL_SOURCES).unwrap();
        assert!(other_epoch.reserve(1).is_none());
        assert_eq!(budget.used(), GLOBAL_SOURCES);
        let source = batch.take_one();
        drop(batch);
        assert_eq!(budget.used(), 1);
        assert!(other_epoch.reserve(GLOBAL_SOURCES).is_none());
        assert_eq!(budget.used(), 1);
        let rest = other_epoch.reserve(GLOBAL_SOURCES - 1).unwrap();
        drop(source);
        drop(rest);
        assert_eq!(budget.used(), 0);
        assert!(budget.reserve(usize::MAX).is_none());
        assert_eq!(budget.used(), 0);
    }
}
