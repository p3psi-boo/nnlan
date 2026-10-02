//! Coalesced FIFO record propagation, paced below the peer's verification limit.
//! Store identities, not serialized versions: sending always reads the latest record.
use super::control::MAX_NODES;
use crate::identity::NodeId;
use std::{
    collections::{BTreeSet, VecDeque},
    time::{Duration, Instant},
};

// At most 200 records/s per neighbor, leaving room under the shared 256/s
// signature admission budget for signed trace requests/replies and jitter.
const SPACING: Duration = Duration::from_millis(5);

pub(super) struct Gossip {
    pending: BTreeSet<NodeId>,
    order: VecDeque<NodeId>,
    next: Instant,
}
impl Gossip {
    pub fn new(local: NodeId, records: impl Iterator<Item = NodeId>, now: Instant) -> Self {
        let mut queue = Self {
            pending: BTreeSet::new(),
            order: VecDeque::new(),
            next: now,
        };
        // A newly connected neighbor first needs our current adjacency record.
        queue.insert(local);
        for node in records {
            queue.insert(node);
        }
        queue
    }
    pub fn insert(&mut self, node: NodeId) {
        if self.pending.len() < MAX_NODES && self.pending.insert(node) {
            self.order.push_back(node);
        }
    }
    pub fn pop(&mut self, now: Instant) -> Option<NodeId> {
        if now < self.next {
            return None;
        }
        let node = self.order.pop_front()?;
        self.pending.remove(&node);
        // No accumulated credit or catch-up burst after a stalled event loop.
        self.next = now + SPACING;
        Some(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Identity, test_id};

    #[test]
    fn refreshes_coalesce_without_reordering_or_starving_other_identities() {
        let now = Instant::now();
        let [local, a, b] = [test_id(0), test_id(1), test_id(2)];
        let mut queue = Gossip::new(local, [b, a, local, b].into_iter(), now);
        assert_eq!(queue.pop(now), Some(local));
        for _ in 0..100 {
            queue.insert(local);
            queue.insert(b);
        }
        assert_eq!(queue.pending.len(), 3);
        assert_eq!(queue.pop(now + SPACING), Some(b));
        queue.insert(b);
        assert_eq!(queue.pop(now + SPACING * 2), Some(a));
        assert_eq!(queue.pop(now + SPACING * 3), Some(local));
        assert_eq!(queue.pop(now + SPACING * 4), Some(b));
        assert!(queue.pending.is_empty());
        assert!(queue.pop(now + SPACING * 5).is_none());
    }
    #[test]
    fn send_rate_is_bounded_without_idle_credit_or_same_tick_retry() {
        let now = Instant::now();
        let local = test_id(0);
        let mut queue = Gossip::new(local, std::iter::empty(), now);
        let mut sent = 0;
        for ms in 0..1000 {
            let at = now + Duration::from_millis(ms);
            if let Some(node) = queue.pop(at) {
                sent += 1;
                queue.insert(node); // Successful refresh or failed-send retry.
                assert!(queue.pop(at).is_none());
            }
        }
        assert_eq!(sent, 200);
        let after_idle = now + Duration::from_secs(100);
        assert_eq!(queue.pop(after_idle), Some(local));
        queue.insert(local);
        assert!(queue.pop(after_idle).is_none());
        assert_eq!(queue.pop(after_idle + SPACING), Some(local));
    }
    #[test]
    fn pending_memory_and_order_share_the_record_capacity() {
        let now = Instant::now();
        let local = test_id(0);
        let mut queue = Gossip::new(local, std::iter::empty(), now);
        for _ in 0..MAX_NODES + 1 {
            queue.insert(Identity::generate().unwrap().node_id());
        }
        assert_eq!(queue.pending.len(), MAX_NODES);
        assert_eq!(queue.order.len(), MAX_NODES);
        assert_eq!(
            queue.order.iter().copied().collect::<BTreeSet<_>>(),
            queue.pending
        );
        assert_eq!(queue.pop(now), Some(local));
        queue.insert(local);
        assert_eq!(queue.pending.len(), MAX_NODES);
        assert_eq!(queue.order.back(), Some(&local));
    }
}
