use anyhow::{Result, ensure};

#[derive(Clone, Copy, Debug)]
pub enum TrafficClass {
    Data,
    Control,
    Probe,
    Fec,
    Retransmission,
}

/// One window of an externally supplied wire-byte budget. FEC and RTX share
/// the same protection allowance, not two independent allowances.
pub struct ProtectionBudget {
    total: u64,
    repair: u64,
}

impl ProtectionBudget {
    pub fn new(total_wire_bytes: u64, protection_basis_points: u16) -> Result<Self> {
        ensure!(
            protection_basis_points <= 3500,
            "protection ratio exceeds the 35% wire budget cap"
        );
        let repair =
            (u128::from(total_wire_bytes) * u128::from(protection_basis_points) / 10_000) as u64;
        Ok(Self {
            total: total_wire_bytes,
            repair,
        })
    }

    /// Includes headers/tags/padding. Failure consumes no budget.
    pub fn admit(&mut self, class: TrafficClass, wire_bytes: u64) -> bool {
        let protected = matches!(class, TrafficClass::Fec | TrafficClass::Retransmission);
        if wire_bytes > self.total || (protected && wire_bytes > self.repair) {
            return false;
        }
        self.total -= wire_bytes;
        if protected {
            self.repair -= wire_bytes;
        }
        true
    }

    pub fn remaining(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_budget_and_failed_admission_are_exact() {
        let mut b = ProtectionBudget::new(1000, 3500).unwrap();
        assert!(b.admit(TrafficClass::Fec, 200));
        assert!(!b.admit(TrafficClass::Retransmission, 151));
        assert!(b.admit(TrafficClass::Retransmission, 150));
        assert!(b.admit(TrafficClass::Data, 600));
        assert!(b.admit(TrafficClass::Control, 50));
        assert!(!b.admit(TrafficClass::Probe, 1));
        assert_eq!(b.remaining(), 0);
        assert!(ProtectionBudget::new(1, 3501).is_err());
        assert!(ProtectionBudget::new(u64::MAX, 3500).is_ok());
    }
}
