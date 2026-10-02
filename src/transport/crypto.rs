//! Noise XX with Ed25519-signed static DH keys and transcript-bound node identities.
use super::wire::{self, DATA, HS1, HS2, HS3, Packet, READY};
use crate::{
    identity::{Identity, NodeId},
    protocol::{ReplayWindow, TransmissionNumber},
};
use anyhow::{Context, Result, ensure};
use snow::{HandshakeState, StatelessTransportState};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
// Frozen protocol domain: product renaming must preserve addresses and peer compatibility.
const DOMAIN: &str = "ggbond.noise-static.v1";
const MAX_PENDING: usize = 64;
const READY_PLAIN: &[u8] = b"ggbond.key-ready.v1";
// DATA never uses this nonce. Reclassifying READY as DATA must not poison its
// replay window; confirmation retransmits use the exact cached ciphertext.
// Noise itself reserves u64::MAX for its rekey primitive.
const READY_NONCE: u64 = u64::MAX - 1;
const HANDSHAKE_TTL: Duration = Duration::from_secs(8);
const RETRY: Duration = Duration::from_millis(400);

struct Completed {
    at: Instant,
    peer: NodeId,
    request: u8,
    reply: Vec<u8>,
}

struct Pending {
    noise: HandshakeState,
    peer: NodeId,
    initiator: bool,
    last: Vec<u8>,
    updated: Instant,
    started: Instant,
}
struct Session {
    cipher: StatelessTransportState,
    peer: NodeId,
    next: u64,
    replay: ReplayWindow,
    born: Instant,
    last_seen: Instant,
    generation: u64,
}
struct Confirmation {
    peer: NodeId,
    deadline: Instant,
    retry_at: Instant,
}
pub struct Crypto {
    local: NodeId,
    key: Zeroizing<Vec<u8>>,
    proof: Vec<u8>,
    pending: BTreeMap<u64, Pending>,
    confirming: BTreeMap<u64, Confirmation>,
    sessions: BTreeMap<u64, Session>,
    active: BTreeMap<NodeId, u64>,
    completed: BTreeMap<u64, Completed>,
    generation: u64,
    recent_inits: VecDeque<Instant>,
}

pub struct HandshakeResult {
    pub reply: Option<Vec<u8>>,
    pub established: Option<NodeId>,
}

impl Crypto {
    pub fn new(identity: &Identity) -> Result<Self> {
        let key = snow::Builder::new(PATTERN.parse()?).generate_keypair()?;
        let mut proof = identity.node_id().as_bytes().to_vec();
        proof.extend_from_slice(&identity.sign(DOMAIN, &key.public));
        Ok(Self {
            local: identity.node_id(),
            key: Zeroizing::new(key.private),
            proof,
            pending: BTreeMap::new(),
            confirming: BTreeMap::new(),
            sessions: BTreeMap::new(),
            active: BTreeMap::new(),
            completed: BTreeMap::new(),
            generation: 0,
            recent_inits: VecDeque::new(),
        })
    }
    pub fn has_session(&self, peer: NodeId) -> bool {
        self.active.contains_key(&peer)
    }
    pub fn session_age(&self, peer: NodeId, now: Instant) -> Option<Duration> {
        self.sessions
            .get(self.active.get(&peer)?)
            .map(|s| now.saturating_duration_since(s.born))
    }
    pub fn pending_for(&self, peer: NodeId) -> bool {
        self.pending.values().any(|p| p.peer == peer)
            || self.confirming.values().any(|s| s.peer == peer)
    }
    pub(crate) fn pending_session(&self, session: u64) -> bool {
        self.pending.contains_key(&session) || self.awaiting_confirmation(session)
    }
    /// A verified winner stops other outgoing candidate handshakes. Incoming
    /// flights remain eligible to complete a simultaneous open.
    pub(crate) fn cancel_initiated(&mut self, peer: NodeId) -> Vec<u64> {
        let ids: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| p.peer == peer && p.initiator)
            .map(|(&id, _)| id)
            .collect();
        for id in &ids {
            self.pending.remove(id);
        }
        ids
    }
    pub fn cancel_pending(&mut self, peer: NodeId) {
        self.pending.retain(|_, pending| pending.peer != peer);
    }
    fn builder(
        &self,
        session: u64,
        initiator: NodeId,
        responder: NodeId,
        is_initiator: bool,
    ) -> Result<HandshakeState> {
        let mut prologue = b"ggbond.noise.v3".to_vec();
        prologue.push(wire::LINK_SCOPE);
        prologue.extend_from_slice(&session.to_be_bytes());
        prologue.extend_from_slice(initiator.as_bytes());
        prologue.extend_from_slice(responder.as_bytes());
        let builder = snow::Builder::new(PATTERN.parse()?)
            .local_private_key(&self.key)?
            .prologue(&prologue)?;
        Ok(if is_initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        })
    }
    pub fn begin(&mut self, peer: NodeId, now: Instant) -> Result<Option<Vec<u8>>> {
        if self.pending_for(peer) {
            return Ok(None);
        }
        self.begin_candidate(peer, now)
    }
    /// Two independent outgoing Noise flights, each pinned to one path by UDP.
    /// Keep separate room for two incoming flights so simultaneous open cannot
    /// deadlock behind a pair of outgoing attempts. Global capacity stays 64.
    pub(crate) fn begin_candidate(
        &mut self,
        peer: NodeId,
        now: Instant,
    ) -> Result<Option<Vec<u8>>> {
        ensure!(peer != self.local, "self handshake");
        if self
            .pending
            .values()
            .filter(|p| p.peer == peer && p.initiator)
            .count()
            + self.confirming.values().filter(|s| s.peer == peer).count()
            >= 2
        {
            return Ok(None);
        }
        ensure!(
            self.pending.len() + self.confirming.len() < MAX_PENDING && self.session_capacity(),
            "session capacity"
        );
        let session = wire::random_id()?;
        ensure!(
            !self.sessions.contains_key(&session) && !self.pending.contains_key(&session),
            "session identifier collision"
        );
        let mut noise = self.builder(session, self.local, peer, true)?;
        let mut msg = [0; 512];
        let n = noise.write_message(&[], &mut msg)?;
        let mut payload = self.local.as_bytes().to_vec();
        payload.extend_from_slice(&msg[..n]);
        // Pad initiation to bound response amplification. Length is fixed and validated.
        payload.resize(256, 0);
        let last = wire::session_packet(HS1, wire::LINK_SCOPE, session, 0, &payload);
        self.pending.insert(
            session,
            Pending {
                noise,
                peer,
                initiator: true,
                last: last.clone(),
                updated: now,
                started: now,
            },
        );
        Ok(Some(last))
    }
    pub fn receive_handshake(
        &mut self,
        bytes: &[u8],
        expected: Option<NodeId>,
        now: Instant,
    ) -> Result<HandshakeResult> {
        let packet = Packet::parse(bytes)?;
        ensure!(packet.scope == wire::LINK_SCOPE, "wrong handshake scope");
        if packet.kind == READY {
            return self.receive_ready(packet, expected, now);
        }
        ensure!(
            packet.number == 0 && matches!(packet.kind, HS1 | HS2 | HS3),
            "wrong handshake context"
        );
        if let Some(done) = self.completed.get(&packet.session) {
            ensure!(
                expected.is_none_or(|id| id == done.peer),
                "wrong completed peer"
            );
            return Ok(HandshakeResult {
                reply: (packet.kind == done.request).then(|| done.reply.clone()),
                established: None,
            });
        }
        if packet.kind == HS1 {
            // A public wire ID is not an identity. Even after the shorter
            // completed-flight cache expires, no initiator may overwrite a
            // live key (and leave another peer's active index pointing at it).
            ensure!(
                !self.sessions.contains_key(&packet.session),
                "session identifier collision"
            );
            ensure!(packet.body.len() == 256, "invalid initiation length");
            let peer = NodeId::from_bytes(packet.body[..32].try_into()?)?;
            ensure!(
                peer != self.local && expected.is_none_or(|id| id == peer),
                "unexpected initiator"
            );
            if let Some(pending) = self.pending.get(&packet.session) {
                ensure!(
                    pending.peer == peer && !pending.initiator,
                    "handshake collision"
                );
                return Ok(HandshakeResult {
                    reply: Some(pending.last.clone()),
                    established: None,
                });
            }
            while self
                .recent_inits
                .front()
                .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(1))
            {
                self.recent_inits.pop_front();
            }
            ensure!(
                self.recent_inits.len() < 32
                    && self.pending.len() + self.confirming.len() < MAX_PENDING
                    && self.session_capacity()
                    && self
                        .pending
                        .values()
                        .filter(|p| p.peer == peer && !p.initiator)
                        .count()
                        < 2,
                "handshake rate/capacity"
            );
            self.recent_inits.push_back(now);
            let mut noise = self.builder(packet.session, peer, self.local, false)?;
            let mut out = [0; 512];
            noise.read_message(&packet.body[32..64], &mut out)?;
            let n = noise.write_message(&self.proof, &mut out)?;
            let reply = wire::session_packet(HS2, wire::LINK_SCOPE, packet.session, 0, &out[..n]);
            self.pending.insert(
                packet.session,
                Pending {
                    noise,
                    peer,
                    initiator: false,
                    last: reply.clone(),
                    updated: now,
                    started: now,
                },
            );
            return Ok(HandshakeResult {
                reply: Some(reply),
                established: None,
            });
        }
        let pending = self
            .pending
            .get_mut(&packet.session)
            .context("unknown handshake")?;
        ensure!(
            expected.is_none_or(|id| id == pending.peer),
            "unexpected handshake peer"
        );
        ensure!(
            packet.kind == if pending.initiator { HS2 } else { HS3 },
            "wrong handshake flight"
        );
        let mut proof = [0; 512];
        let n = pending.noise.read_message(packet.body, &mut proof)?;
        ensure!(
            n == 96 && &proof[..32] == pending.peer.as_bytes(),
            "wrong signed identity"
        );
        pending.peer.verify(
            DOMAIN,
            pending
                .noise
                .get_remote_static()
                .context("missing static key")?,
            proof[32..96].try_into()?,
        )?;
        let mut pending = self
            .pending
            .remove(&packet.session)
            .context("missing handshake")?;
        let mut reply = if pending.initiator {
            let mut out = [0; 512];
            let n = pending.noise.write_message(&self.proof, &mut out)?;
            Some(wire::session_packet(
                HS3,
                wire::LINK_SCOPE,
                packet.session,
                0,
                &out[..n],
            ))
        } else {
            None
        };
        let peer = pending.peer;
        let cipher = pending.noise.into_stateless_transport_mode()?;
        let generation = self
            .generation
            .checked_add(1)
            .context("key generation exhausted")?;
        self.make_session_room(peer)?;
        self.generation = generation;
        self.sessions.insert(
            packet.session,
            Session {
                cipher,
                peer,
                next: 0,
                replay: ReplayWindow::default(),
                born: now,
                last_seen: now,
                generation,
            },
        );
        if pending.initiator {
            self.confirming.insert(
                packet.session,
                Confirmation {
                    peer,
                    deadline: pending.started + HANDSHAKE_TTL,
                    retry_at: now + RETRY,
                },
            );
        } else {
            self.active.insert(peer, packet.session);
            let session = &self.sessions[&packet.session];
            let mut proof = vec![0; READY_PLAIN.len() + 16];
            session
                .cipher
                .write_message(READY_NONCE, READY_PLAIN, &mut proof)?;
            reply = Some(wire::session_packet(
                READY,
                wire::LINK_SCOPE,
                packet.session,
                READY_NONCE,
                &proof,
            ));
        }
        self.completed.insert(
            packet.session,
            Completed {
                at: now,
                peer,
                request: packet.kind,
                reply: reply.clone().expect("final flight or readiness proof"),
            },
        );
        Ok(HandshakeResult {
            reply,
            // HS2 proves identity, not that the responder has received HS3.
            established: (!pending.initiator).then_some(peer),
        })
    }
    pub(crate) fn awaiting_confirmation(&self, id: u64) -> bool {
        self.confirming.contains_key(&id)
    }
    pub(crate) fn discard_unconfirmed(&mut self, id: u64) {
        if self.confirming.remove(&id).is_some() {
            self.sessions.remove(&id);
            self.completed.remove(&id);
        }
    }
    /// Call only after authenticating this session AND checking the enclosing
    /// transport's pinned endpoint. Old receive epochs
    /// never replace a newer selected sending key.
    pub(crate) fn confirm_authenticated(
        &mut self,
        id: u64,
        now: Instant,
    ) -> Result<Option<NodeId>> {
        let Some(confirm) = self.confirming.get(&id) else {
            return Ok(None);
        };
        ensure!(now < confirm.deadline, "confirmation expired");
        let s = self.sessions.get(&id).context("unknown confirmation")?;
        self.confirming.remove(&id);
        let peer = s.peer;
        let generation = s.generation;
        if self
            .active
            .get(&peer)
            .and_then(|active| self.sessions.get(active))
            .is_none_or(|active| generation > active.generation)
        {
            self.active.insert(peer, id);
        }
        Ok(Some(peer))
    }
    fn receive_ready(
        &mut self,
        packet: Packet<'_>,
        expected: Option<NodeId>,
        now: Instant,
    ) -> Result<HandshakeResult> {
        ensure!(
            packet.number == READY_NONCE && packet.body.len() == READY_PLAIN.len() + 16,
            "invalid readiness proof"
        );
        let session = self
            .sessions
            .get(&packet.session)
            .context("unknown readiness session")?;
        ensure!(
            expected.is_none_or(|peer| peer == session.peer),
            "wrong readiness peer"
        );
        ensure!(
            now.saturating_duration_since(session.born) < Duration::from_secs(300),
            "session key expired"
        );
        let mut plain = [0; 64];
        let size = session
            .cipher
            .read_message(READY_NONCE, packet.body, &mut plain)?;
        ensure!(&plain[..size] == READY_PLAIN, "wrong readiness domain");
        Ok(HandshakeResult {
            reply: None,
            established: self.confirm_authenticated(packet.session, now)?,
        })
    }
    fn session_capacity(&self) -> bool {
        self.sessions.len() < 8192 || self.oldest_inactive(None).is_some()
    }
    fn oldest_inactive(&self, peer: Option<NodeId>) -> Option<u64> {
        self.sessions
            .iter()
            .filter(|(id, session)| {
                peer.is_none_or(|p| p == session.peer) && self.active.get(&session.peer) != Some(id)
            })
            .min_by_key(|(id, session)| (session.born, **id))
            .map(|(&id, _)| id)
    }
    /// Only call after the new handshake proves the pinned identity. Unverified
    /// initiations must never evict established keys. Keep the active key until
    /// its replacement is installed, retaining at most three older generations.
    fn make_session_room(&mut self, peer: NodeId) -> Result<()> {
        if self.sessions.values().filter(|s| s.peer == peer).count() >= 4 {
            let id = self
                .oldest_inactive(Some(peer))
                .context("peer key capacity")?;
            self.discard_unconfirmed(id);
            self.sessions.remove(&id);
        }
        if self.sessions.len() >= 8192 {
            let id = self.oldest_inactive(None).context("active key capacity")?;
            self.discard_unconfirmed(id);
            self.sessions.remove(&id);
        }
        Ok(())
    }
    pub fn encrypt(&mut self, peer: NodeId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let id = *self.active.get(&peer).context("session not established")?;
        self.encrypt_session(id, plaintext)
    }
    pub fn active_session(&self, peer: NodeId) -> Option<u64> {
        self.active.get(&peer).copied()
    }
    pub fn contains_session(&self, session: u64) -> bool {
        self.sessions.contains_key(&session)
    }
    pub fn encrypt_session(&mut self, id: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self.sessions.get_mut(&id).context("session expired")?;
        ensure!(
            !self.confirming.contains_key(&id),
            "remote key not confirmed"
        );
        ensure!(
            Instant::now().saturating_duration_since(session.born) < Duration::from_secs(300),
            "session key expired"
        );
        let nonce = session.next;
        ensure!(nonce < READY_NONCE, "session counter exhausted");
        session.next = nonce.checked_add(1).context("session counter exhausted")?;
        // Write ciphertext directly behind its unchanged wire header: no second
        // allocation/copy for every link packet.
        let mut out = Vec::with_capacity(24 + plaintext.len() + 16);
        out.extend_from_slice(wire::MAGIC);
        out.extend_from_slice(&[DATA, wire::LINK_SCOPE, 0, 0]);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&nonce.to_be_bytes());
        out.resize(24 + plaintext.len() + 16, 0);
        let n = session
            .cipher
            .write_message(nonce, plaintext, &mut out[24..])?;
        out.truncate(24 + n);
        Ok(out)
    }
    pub fn decrypt(&mut self, bytes: &[u8], now: Instant) -> Result<(NodeId, Vec<u8>)> {
        let packet = Packet::parse(bytes)?;
        ensure!(
            packet.kind == DATA && packet.scope == wire::LINK_SCOPE && packet.number < READY_NONCE,
            "not session data"
        );
        let session = self
            .sessions
            .get_mut(&packet.session)
            .context("unknown session")?;
        ensure!(
            now.saturating_duration_since(session.born) < Duration::from_secs(300),
            "session key expired"
        );
        ensure!(
            session
                .replay
                .would_accept(TransmissionNumber(packet.number)),
            "replayed packet"
        );
        let mut out = vec![0; packet.body.len()];
        let n = session
            .cipher
            .read_message(packet.number, packet.body, &mut out)?;
        ensure!(
            session
                .replay
                .record_authenticated(TransmissionNumber(packet.number)),
            "replay race"
        );
        session.last_seen = now;
        out.truncate(n);
        Ok((session.peer, out))
    }
    pub fn maintenance(&mut self, now: Instant) -> Vec<(NodeId, Vec<u8>)> {
        self.pending
            .retain(|_, p| now.duration_since(p.started) < HANDSHAKE_TTL);
        self.completed
            .retain(|_, done| now.duration_since(done.at) < Duration::from_secs(10));
        let expired: Vec<_> = self
            .confirming
            .iter()
            .filter(|(_, c)| now >= c.deadline)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.discard_unconfirmed(id);
        }
        let active = &self.active;
        // Retain active send keys and recently used receive epochs. Adjacent
        // peers send keepalives, including across simultaneous key rotation.
        self.sessions.retain(|id, s| {
            now.duration_since(s.born) < Duration::from_secs(300)
                && (active.get(&s.peer) == Some(id)
                    || now.duration_since(s.last_seen) < Duration::from_secs(30))
        });
        self.active.retain(|_, id| self.sessions.contains_key(id));
        let mut retries = vec![];
        for (&id, s) in &mut self.confirming {
            if now >= s.retry_at {
                if let Some(done) = self.completed.get(&id) {
                    retries.push((s.peer, done.reply.clone()));
                }
                s.retry_at = now + RETRY;
            }
        }
        for p in self.pending.values_mut() {
            if now.duration_since(p.updated) >= RETRY {
                retries.push((p.peer, p.last.clone()));
                p.updated = now;
            }
        }
        retries
    }
    pub fn forget(&mut self, peer: NodeId) {
        self.active.remove(&peer);
        self.completed.retain(|_, done| done.peer != peer);
        self.sessions.retain(|_, s| s.peer != peer);
        self.confirming.retain(|_, s| s.peer != peer);
        self.pending.retain(|_, p| p.peer != peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accelerated_chachapoly_matches_existing_wire_bytes() {
        use snow::{
            params::CipherChoice,
            resolvers::{CryptoResolver, DefaultResolver, RingResolver},
        };
        let mut old = DefaultResolver
            .resolve_cipher(&CipherChoice::ChaChaPoly)
            .unwrap();
        let mut fast = RingResolver
            .resolve_cipher(&CipherChoice::ChaChaPoly)
            .unwrap();
        old.set(&[37; 32]);
        fast.set(&[37; 32]);
        for size in [0, 1, 64, 127, 128, 548, 1232, 32768] {
            let plain: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            for nonce in [0, 1, 1 << 32, u64::MAX - 2] {
                let mut before = vec![0; size + 16];
                let mut after = vec![0; size + 16];
                assert_eq!(
                    old.encrypt(nonce, b"bound header", &plain, &mut before),
                    size + 16
                );
                assert_eq!(
                    fast.encrypt(nonce, b"bound header", &plain, &mut after),
                    size + 16
                );
                assert_eq!(before, after);
                let mut decoded = vec![0; size + 16];
                assert_eq!(
                    fast.decrypt(nonce, b"bound header", &before, &mut decoded)
                        .unwrap(),
                    size
                );
                assert_eq!(&decoded[..size], plain);
                assert_eq!(
                    old.decrypt(nonce, b"bound header", &after, &mut decoded)
                        .unwrap(),
                    size
                );
                after[size] ^= 1;
                assert!(
                    fast.decrypt(nonce, b"bound header", &after, &mut decoded)
                        .is_err()
                );
                assert!(
                    fast.decrypt(nonce, b"changed header", &before, &mut decoded)
                        .is_err()
                );
            }
        }
    }

    fn handshake(a: &mut Crypto, b: &mut Crypto, aid: NodeId, bid: NodeId, now: Instant) {
        let one = a.begin(bid, now).unwrap().unwrap();
        let two = b
            .receive_handshake(&one, Some(aid), now)
            .unwrap()
            .reply
            .unwrap();
        let three = a
            .receive_handshake(&two, Some(bid), now)
            .unwrap()
            .reply
            .unwrap();
        let ready = b
            .receive_handshake(&three, Some(aid), now)
            .unwrap()
            .reply
            .unwrap();
        a.receive_handshake(&ready, Some(bid), now).unwrap();
    }
    #[test]
    fn key_rotation_retains_only_bounded_old_receive_epochs() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut ca = Crypto::new(&a).unwrap();
        let mut cb = Crypto::new(&b).unwrap();
        let now = Instant::now();
        handshake(&mut ca, &mut cb, a.node_id(), b.node_id(), now);
        let old = ca.active_session(b.node_id()).unwrap();
        let delayed = ca.encrypt(b.node_id(), b"delayed").unwrap();
        let later = now + Duration::from_secs(120);
        handshake(&mut ca, &mut cb, a.node_id(), b.node_id(), later);
        assert_ne!(ca.active_session(b.node_id()), Some(old));
        assert_eq!(cb.decrypt(&delayed, later).unwrap().1, b"delayed");
        let new = ca.encrypt(b.node_id(), b"new key").unwrap();
        cb.maintenance(later + Duration::from_secs(31));
        assert!(!cb.contains_session(old));
        assert!(cb.decrypt(&new, later + Duration::from_secs(31)).is_ok());
        let expired = ca.encrypt(b.node_id(), b"expired").unwrap();
        assert!(
            cb.decrypt(&expired, later + Duration::from_secs(300))
                .is_err()
        );
    }

    #[test]
    fn rapid_authenticated_rekeys_evict_only_the_oldest_inactive_epoch() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut ca = Crypto::new(&a).unwrap();
        let mut cb = Crypto::new(&b).unwrap();
        let now = Instant::now();
        let mut delayed = vec![];
        for generation in 0..20 {
            let at = now + Duration::from_millis(generation);
            handshake(&mut ca, &mut cb, a.node_id(), b.node_id(), at);
            delayed.push(
                ca.encrypt(b.node_id(), b"queued before next rekey")
                    .unwrap(),
            );
            assert_eq!(ca.sessions.len(), (generation as usize + 1).min(4));
            assert_eq!(cb.sessions.len(), ca.sessions.len());
        }
        for (generation, packet) in delayed.iter().enumerate() {
            assert_eq!(
                cb.decrypt(packet, now + Duration::from_secs(1)).is_ok(),
                generation >= 16
            );
        }
        let reply = cb.encrypt(a.node_id(), b"latest key still works").unwrap();
        assert_eq!(
            ca.decrypt(&reply, now + Duration::from_secs(1)).unwrap().1,
            b"latest key still works"
        );
    }
    #[test]
    fn unverified_rekey_never_evicts_established_keys() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut ca = Crypto::new(&a).unwrap();
        let mut cb = Crypto::new(&b).unwrap();
        let now = Instant::now();
        for generation in 0..4 {
            handshake(
                &mut ca,
                &mut cb,
                a.node_id(),
                b.node_id(),
                now + Duration::from_millis(generation),
            );
        }
        let keys: Vec<_> = ca.sessions.keys().copied().collect();
        let one = ca
            .begin(b.node_id(), now + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let mut two = cb
            .receive_handshake(&one, Some(a.node_id()), now + Duration::from_secs(1))
            .unwrap()
            .reply
            .unwrap();
        *two.last_mut().unwrap() ^= 1;
        assert!(
            ca.receive_handshake(&two, Some(b.node_id()), now + Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(ca.sessions.keys().copied().collect::<Vec<_>>(), keys);
        assert_eq!(cb.sessions.keys().copied().collect::<Vec<_>>(), keys);
        let packet = ca.encrypt(b.node_id(), b"uninterrupted").unwrap();
        assert_eq!(
            cb.decrypt(&packet, now + Duration::from_secs(1)).unwrap().1,
            b"uninterrupted"
        );
    }
    #[test]
    fn candidate_flights_have_directional_and_global_bounds() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let now = Instant::now();
        let mut ca = Crypto::new(&a).unwrap();
        let mut cb = Crypto::new(&b).unwrap();
        let first = ca.begin_candidate(b.node_id(), now).unwrap().unwrap();
        let second = ca.begin_candidate(b.node_id(), now).unwrap().unwrap();
        assert_ne!(
            Packet::parse(&first).unwrap().session,
            Packet::parse(&second).unwrap().session
        );
        assert!(ca.begin_candidate(b.node_id(), now).unwrap().is_none());
        assert!(ca.begin(b.node_id(), now).unwrap().is_none());
        for _ in 0..2 {
            let incoming = cb.begin_candidate(a.node_id(), now).unwrap().unwrap();
            assert!(
                ca.receive_handshake(&incoming, Some(b.node_id()), now)
                    .unwrap()
                    .reply
                    .is_some()
            );
        }
        assert_eq!(ca.pending.len(), 4);
        let mut third = Crypto::new(&b).unwrap();
        let incoming = third.begin(a.node_id(), now).unwrap().unwrap();
        assert!(
            ca.receive_handshake(&incoming, Some(b.node_id()), now)
                .is_err()
        );
        assert_eq!(ca.cancel_initiated(b.node_id()).len(), 2);
        assert_eq!(ca.pending.len(), 2);
        assert!(ca.pending.values().all(|p| !p.initiator));
        ca.maintenance(now + Duration::from_secs(8));
        assert!(ca.pending.is_empty());

        for _ in 0..32 {
            let peer = Identity::generate().unwrap().node_id();
            for _ in 0..2 {
                assert!(ca.begin_candidate(peer, now).unwrap().is_some());
            }
        }
        assert_eq!(ca.pending.len(), MAX_PENDING);
        assert!(ca.begin_candidate(b.node_id(), now).is_err());
    }
    #[test]
    fn lost_handshakes_retry_then_release_capacity() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut crypto = Crypto::new(&a).unwrap();
        let now = Instant::now();
        let first = crypto.begin(b.node_id(), now).unwrap().unwrap();
        assert!(crypto.begin(b.node_id(), now).unwrap().is_none());
        assert!(
            crypto
                .maintenance(now + Duration::from_millis(399))
                .is_empty()
        );
        assert_eq!(
            crypto.maintenance(now + Duration::from_millis(400)),
            vec![(b.node_id(), first)]
        );
        crypto.maintenance(now + Duration::from_secs(8));
        assert!(!crypto.pending_for(b.node_id()));
        assert!(
            crypto
                .begin(b.node_id(), now + Duration::from_secs(9))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn real_xx_pin_replay_and_fresh_retransmission_nonce() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let mut ca = Crypto::new(&a).unwrap();
        let mut cb = Crypto::new(&b).unwrap();
        let now = Instant::now();
        let one = ca.begin(b.node_id(), now).unwrap().unwrap();
        let two = cb
            .receive_handshake(&one, None, now)
            .unwrap()
            .reply
            .unwrap();
        let three = ca
            .receive_handshake(&two, Some(b.node_id()), now)
            .unwrap()
            .reply
            .unwrap();
        let ready = cb
            .receive_handshake(&three, Some(a.node_id()), now)
            .unwrap()
            .reply
            .unwrap();
        ca.receive_handshake(&ready, Some(b.node_id()), now)
            .unwrap();
        let encrypted = ca.encrypt(b.node_id(), b"hello").unwrap();
        assert_eq!(cb.decrypt(&encrypted, now).unwrap().1, b"hello");
        assert!(cb.decrypt(&encrypted, now).is_err());
        let mut corrupt = ca.encrypt(b.node_id(), b"world").unwrap();
        corrupt[25] ^= 1;
        assert!(cb.decrypt(&corrupt, now).is_err());
        assert!(
            cb.decrypt(&ca.encrypt(b.node_id(), b"next").unwrap(), now)
                .is_ok()
        );
    }
}

#[cfg(test)]
mod ready_tests;
