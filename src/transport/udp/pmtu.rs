//! Per-direction, per-authenticated-path packetization-layer MTU discovery.
//! Only a matching encrypted acknowledgement raises the usable datagram size.
use crate::transport::{
    link::frame::{DATAGRAM_OVERHEAD, MIN_UDP},
    wire::{self, BASE_UDP, MAX_UDP},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::time::{Duration, Instant};

pub const TAG: u8 = 254;
const PROBE: u8 = 1;
const ACK: u8 = 2;
const HEADER: usize = 12;
const TIMEOUT: Duration = Duration::from_secs(1);
const VERIFY: Duration = Duration::from_secs(5);
const RAISE: Duration = Duration::from_secs(60);
const PRECISION: usize = 16;

#[derive(Clone, Copy)]
struct Pending {
    size: usize,
    token: u64,
    at: Instant,
    attempts: u8,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub maximum_udp_payload: usize,
    pub udp_payload: usize,
    pub confirmed: bool,
    pub probing: Option<usize>,
    pub probes_sent: u64,
    pub probes_acked: u64,
    pub failed_sizes: u64,
    pub reductions: u64,
}

pub struct PathMtu {
    current: usize,
    upper: usize,
    confirmed: bool,
    pending: Option<Pending>,
    next: Instant,
    raise_at: Instant,
    probes_sent: u64,
    probes_acked: u64,
    failed_sizes: u64,
    reductions: u64,
}
impl PathMtu {
    pub fn new(now: Instant) -> Self {
        Self {
            current: MIN_UDP,
            upper: MAX_UDP,
            confirmed: false,
            pending: None,
            next: now,
            raise_at: now + RAISE,
            probes_sent: 0,
            probes_acked: 0,
            failed_sizes: 0,
            reductions: 0,
        }
    }
    pub fn limit(&self) -> usize {
        self.current
    }
    /// Keys may change without changing the authenticated endpoint pair. Keep
    /// the proven path limit and failure ceiling, but never carry a pending
    /// probe across keys: its replacement needs a fresh token/current-epoch ACK.
    pub fn rekey(&mut self, now: Instant) {
        self.pending = None;
        self.next = now;
    }
    pub fn status(&self) -> Status {
        Status {
            maximum_udp_payload: MAX_UDP,
            udp_payload: self.current,
            confirmed: self.confirmed,
            probing: self.pending.map(|p| p.size),
            probes_sent: self.probes_sent,
            probes_acked: self.probes_acked,
            failed_sizes: self.failed_sizes,
            reductions: self.reductions,
        }
    }
    pub fn poll(&mut self, now: Instant) -> Result<Option<Vec<u8>>> {
        if let Some(p) = self.pending {
            if now.saturating_duration_since(p.at) < TIMEOUT {
                return Ok(None);
            }
            if p.attempts >= 3 {
                self.failed(p.size, now);
                return Ok(None);
            }
            self.pending = Some(Pending {
                at: now,
                attempts: p.attempts + 1,
                ..p
            });
        } else {
            if now < self.next {
                return Ok(None);
            }
            if now >= self.raise_at {
                self.upper = MAX_UDP;
                self.raise_at = now + RAISE;
            }
            let size = if !self.confirmed || self.upper - self.current <= PRECISION {
                self.current
            } else if self.current < BASE_UDP && self.upper >= BASE_UDP {
                // Establish the original GGB3 ceiling before trying extensions.
                // An older receiver ignores larger probes; keep its exact proven
                // size instead of binary-searching to just below it.
                BASE_UDP
            } else if self.upper == MAX_UDP {
                MAX_UDP
            } else {
                self.current + (self.upper - self.current).div_ceil(2)
            };
            self.pending = Some(Pending {
                size,
                token: wire::random_id()?,
                at: now,
                attempts: 1,
            });
        }
        let p = self.pending.expect("probe scheduled");
        self.probes_sent += 1;
        let mut bytes = header(PROBE, p.token, p.size);
        bytes.resize(p.size - DATAGRAM_OVERHEAD, 0);
        Ok(Some(bytes))
    }
    pub fn acknowledge(&mut self, token: u64, size: usize, now: Instant) -> bool {
        let Some(p) = self.pending else {
            return false;
        };
        if p.token != token || p.size != size || now.saturating_duration_since(p.at) >= TIMEOUT {
            return false;
        }
        self.pending = None;
        self.current = size;
        self.confirmed = true;
        self.probes_acked += 1;
        self.next = if self.upper - self.current > PRECISION {
            now + Duration::from_millis(20)
        } else {
            now + VERIFY
        };
        true
    }
    // A local EMSGSIZE can reduce a size, but cannot authenticate a larger size.
    pub fn too_big(&mut self, size: usize, now: Instant) {
        if (MIN_UDP..=MAX_UDP).contains(&size) {
            self.failed(size, now);
        }
    }
    fn failed(&mut self, size: usize, now: Instant) {
        self.pending = None;
        self.failed_sizes += 1;
        self.upper = self.upper.min(size.saturating_sub(1)).max(MIN_UDP);
        if size <= self.current {
            self.reductions += u64::from(self.current > MIN_UDP);
            self.current = MIN_UDP;
            self.confirmed = false;
        }
        self.next = if size == MIN_UDP {
            now + VERIFY
        } else {
            now + Duration::from_millis(20)
        };
    }
}
fn header(kind: u8, token: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![TAG, kind];
    bytes.extend_from_slice(&token.to_be_bytes());
    bytes.extend_from_slice(&(size as u16).to_be_bytes());
    bytes
}

pub enum Control {
    Probe { reply: Vec<u8> },
    Ack { token: u64, size: usize },
}
impl Control {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= HEADER && bytes[0] == TAG,
            "PMTU control header"
        );
        let token = u64::from_be_bytes(bytes[2..10].try_into()?);
        let size = usize::from(u16::from_be_bytes(bytes[10..12].try_into()?));
        ensure!((MIN_UDP..=MAX_UDP).contains(&size), "PMTU probe size");
        match bytes[1] {
            PROBE => {
                ensure!(
                    bytes.len() + DATAGRAM_OVERHEAD == size
                        && bytes[HEADER..].iter().all(|&b| b == 0),
                    "PMTU probe padding/length"
                );
                Ok(Self::Probe {
                    reply: header(ACK, token, size),
                })
            }
            ACK => {
                ensure!(bytes.len() == HEADER, "PMTU ack length");
                Ok(Self::Ack { token, size })
            }
            _ => anyhow::bail!("PMTU control kind"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn deliver(path: &mut PathMtu, probe: &[u8], now: Instant) {
        let Control::Probe { reply } = Control::decode(probe).unwrap() else {
            panic!()
        };
        let Control::Ack { token, size } = Control::decode(&reply).unwrap() else {
            panic!()
        };
        assert!(path.acknowledge(token, size, now));
    }
    #[test]
    fn legacy_peer_or_minimum_ipv6_path_keeps_exact_proven_ceiling() {
        let start = Instant::now();
        let mut path = PathMtu::new(start);
        let mut base_confirmed = false;
        for ms in (0..75_000).step_by(20) {
            let now = start + Duration::from_millis(ms);
            if let Some(probe) = path.poll(now).unwrap()
                && probe.len() + DATAGRAM_OVERHEAD <= BASE_UDP
            {
                deliver(&mut path, &probe, now);
            }
            base_confirmed |= path.limit() == BASE_UDP;
            if base_confirmed {
                // Failed extension probes and the periodic raise attempt must
                // never discard the working 1232-byte path or invent proof.
                assert_eq!(path.limit(), BASE_UDP);
                assert!(path.status().confirmed);
            }
        }
        assert!(base_confirmed);
        assert!(path.status().failed_sizes > 0);
    }
    #[test]
    fn full_path_requires_matching_fresh_proof_and_rejects_malformed_probes() {
        let now = Instant::now();
        let mut path = PathMtu::new(now);
        assert!(!path.acknowledge(0, MAX_UDP, now));
        let probe = path.poll(now).unwrap().unwrap();
        assert_eq!(probe.len() + DATAGRAM_OVERHEAD, MIN_UDP);
        assert!(Control::decode(&probe[..probe.len() - 1]).is_err());
        assert!(!path.acknowledge(0, MIN_UDP, now));
        deliver(&mut path, &probe, now);
        let later = now + Duration::from_millis(20);
        let probe = path.poll(later).unwrap().unwrap();
        assert_eq!(probe.len() + DATAGRAM_OVERHEAD, BASE_UDP);
        deliver(&mut path, &probe, later);
        let later = later + Duration::from_millis(20);
        let probe = path.poll(later).unwrap().unwrap();
        assert_eq!(probe.len() + DATAGRAM_OVERHEAD, MAX_UDP);
        deliver(&mut path, &probe, later);
        assert_eq!(path.limit(), MAX_UDP);
        assert_eq!(path.status().probes_acked, 3);
        assert!(path.poll(later + Duration::from_secs(1)).unwrap().is_none());
    }
    #[test]
    fn rekey_preserves_only_proven_size_and_invalidates_pending_proof() {
        let now = Instant::now();
        let mut path = PathMtu::new(now);
        let probe = path.poll(now).unwrap().unwrap();
        deliver(&mut path, &probe, now);
        let now = now + Duration::from_millis(20);
        let probe = path.poll(now).unwrap().unwrap();
        deliver(&mut path, &probe, now);
        let now = now + Duration::from_millis(20);
        path.poll(now).unwrap().unwrap();
        let stale = path.pending.unwrap();
        assert_eq!(stale.size, MAX_UDP);

        path.rekey(now);
        assert_eq!(path.limit(), BASE_UDP);
        assert!(path.status().confirmed);
        assert!(path.pending.is_none());
        assert!(!path.acknowledge(stale.token, stale.size, now));
        let fresh = path.poll(now).unwrap().unwrap();
        assert_ne!(path.pending.unwrap().token, stale.token);
        assert!(!path.acknowledge(stale.token, stale.size, now));
        deliver(&mut path, &fresh, now);
        assert_eq!(path.limit(), MAX_UDP);

        path.rekey(now);
        assert_eq!(path.limit(), MAX_UDP);
        assert!(path.status().confirmed);
        assert_eq!(path.status().probes_acked, 3);
        let verify = path.poll(now).unwrap().unwrap();
        deliver(&mut path, &verify, now);
        assert_eq!(path.status().probes_acked, 4);
    }
    #[test]
    fn rekey_keeps_failure_ceiling_and_does_not_override_path_reduction() {
        let now = Instant::now();
        let mut path = PathMtu::new(now);
        let probe = path.poll(now).unwrap().unwrap();
        deliver(&mut path, &probe, now);
        path.too_big(900, now);
        let raise_at = path.raise_at;
        path.rekey(now);
        assert_eq!(path.upper, 899);
        assert_eq!(path.raise_at, raise_at);
        assert_eq!(path.status().failed_sizes, 1);
        let probe = path.poll(now).unwrap().unwrap();
        assert!(probe.len() + DATAGRAM_OVERHEAD < 900);
        deliver(&mut path, &probe, now);
        assert!(path.limit() > MIN_UDP);

        path.too_big(path.limit(), now);
        path.rekey(now);
        assert_eq!(path.limit(), MIN_UDP);
        assert!(!path.status().confirmed);
        assert_eq!(path.status().reductions, 1);
        let probe = path.poll(now).unwrap().unwrap();
        assert_eq!(probe.len() + DATAGRAM_OVERHEAD, MIN_UDP);
    }
    #[test]
    fn lossy_probes_blackhole_shrink_and_later_growth_converge() {
        let now = Instant::now();
        let mut path = PathMtu::new(now);
        for ms in (0..160_000).step_by(20) {
            let t = now + Duration::from_millis(ms);
            let capacity = if ms < 20_000 {
                900
            } else if ms < 80_000 {
                620
            } else {
                MAX_UDP
            };
            if let Some(probe) = path.poll(t).unwrap() {
                // Lose the first probe to each size as well as oversize probes.
                if probe.len() + DATAGRAM_OVERHEAD <= capacity && path.pending.unwrap().attempts > 1
                {
                    deliver(&mut path, &probe, t);
                }
            }
            if ms == 19_980 {
                assert!((884..=900).contains(&path.limit()));
            }
            if ms == 59_980 {
                assert!((604..=620).contains(&path.limit()));
            }
        }
        assert_eq!(path.limit(), MAX_UDP);
        assert!(path.status().reductions > 0);
    }
    #[test]
    fn minimum_mtu_failure_is_bounded_and_local_errors_never_raise() {
        let now = Instant::now();
        let mut path = PathMtu::new(now);
        let mut sends = 0;
        for ms in 0..20_000 {
            let t = now + Duration::from_millis(ms);
            if let Some(probe) = path.poll(t).unwrap() {
                sends += 1;
                path.too_big(probe.len() + DATAGRAM_OVERHEAD, t);
            }
        }
        assert_eq!(sends, 4);
        assert_eq!(path.limit(), MIN_UDP);
        assert!(!path.status().confirmed);
    }
}
