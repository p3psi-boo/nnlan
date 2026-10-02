//! Shared protocol invariants. Authenticated wire transport lives in `transport`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketId(pub u64);

/// Each send, including a retransmission, needs a fresh transmission number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmissionNumber(pub u64);

#[derive(Default)]
pub struct SendSequence {
    next: u64,
}

impl SendSequence {
    /// u64::MAX is reserved. Exhaustion requires a new key/session, never wrapping.
    pub fn allocate(&mut self) -> Option<TransmissionNumber> {
        let next = self.next.checked_add(1)?;
        let result = TransmissionNumber(self.next);
        self.next = next;
        Some(result)
    }
}

/// Fixed 8192-packet replay window (1 KiB per session), including reordered UDP.
/// Advancing clears only the overwritten ring segments, never shifts the bitmap.
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: [u64; 128],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            seen: [0; 128],
        }
    }
}

impl ReplayWindow {
    pub fn would_accept(&self, sequence: TransmissionNumber) -> bool {
        let n = sequence.0;
        if n == u64::MAX {
            return false;
        }
        let Some(highest) = self.highest else {
            return true;
        };
        n > highest
            || (highest - n < 8192
                && self.seen[(n % 8192) as usize / 64] & (1_u64 << (n % 64)) == 0)
    }

    /// Only commit AFTER successful AEAD authentication. Untrusted sequence numbers
    /// must never advance this window; create a distinct window for each key epoch.
    pub fn record_authenticated(&mut self, sequence: TransmissionNumber) -> bool {
        if !self.would_accept(sequence) {
            return false;
        }
        let n = sequence.0;
        match self.highest {
            None => {
                self.highest = Some(n);
            }
            Some(highest) if n > highest => {
                let gap = n - highest;
                if gap >= 8192 {
                    self.seen.fill(0);
                } else {
                    let mut position = (highest + 1) % 8192;
                    let mut remaining = gap;
                    while remaining > 0 {
                        let offset = position % 64;
                        let count = remaining.min(64 - offset);
                        let mask = if count == 64 {
                            u64::MAX
                        } else {
                            ((1_u64 << count) - 1) << offset
                        };
                        self.seen[position as usize / 64] &= !mask;
                        remaining -= count;
                        position = (position + count) % 8192;
                    }
                }
                self.highest = Some(n);
            }
            Some(_) => (),
        }
        self.seen[(n % 8192) as usize / 64] |= 1_u64 << (n % 64);
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HopLimit(std::num::NonZeroU8);

impl HopLimit {
    pub fn new(value: u8) -> Option<Self> {
        std::num::NonZeroU8::new(value).map(Self)
    }
    /// Only intermediate relays decrement. A destination consumes its own packet.
    pub fn forwarded(self) -> Option<Self> {
        Self::new(self.0.get() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_duplicates_reordering_old_packets_and_forged_high_numbers() {
        let mut w = ReplayWindow::default();
        assert!(w.record_authenticated(TransmissionNumber(10)));
        assert!(w.record_authenticated(TransmissionNumber(8)));
        assert!(!w.record_authenticated(TransmissionNumber(8)));
        assert!(w.would_accept(TransmissionNumber(1_000_000))); // Authentication fails; no commit.
        assert!(w.record_authenticated(TransmissionNumber(9)));
        assert!(w.record_authenticated(TransmissionNumber(9000)));
        assert!(!w.would_accept(TransmissionNumber(808)));
        assert!(w.record_authenticated(TransmissionNumber(809)));
        assert!(!w.record_authenticated(TransmissionNumber(u64::MAX)));
    }

    #[test]
    fn replay_ring_matches_reference_across_wraps_and_gaps() {
        let mut window = ReplayWindow::default();
        let mut reference = std::collections::BTreeSet::new();
        let mut highest = None;
        let mut random = 12345_u64;
        for step in 0..40_000_u64 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let n = (step * 7).saturating_sub(random % 9000);
            let expected =
                highest.is_none_or(|h| n > h || (h - n < 8192 && !reference.contains(&n)));
            assert_eq!(window.would_accept(TransmissionNumber(n)), expected);
            assert_eq!(window.record_authenticated(TransmissionNumber(n)), expected);
            if expected {
                reference.insert(n);
                highest = Some(highest.unwrap_or(0).max(n));
            }
        }
    }

    #[test]
    fn counters_and_hops_never_wrap() {
        let mut sequence = SendSequence { next: u64::MAX - 1 };
        assert_eq!(sequence.allocate(), Some(TransmissionNumber(u64::MAX - 1)));
        assert!(sequence.allocate().is_none());
        assert!(HopLimit::new(0).is_none());
        assert!(HopLimit::new(1).unwrap().forwarded().is_none());
    }
}
