use super::*;

fn final_flight(a: &mut Crypto, b: &mut Crypto, aid: NodeId, bid: NodeId, now: Instant) -> Vec<u8> {
    let one = a.begin(bid, now).unwrap().unwrap();
    let two = b
        .receive_handshake(&one, Some(aid), now)
        .unwrap()
        .reply
        .unwrap();
    let result = a.receive_handshake(&two, Some(bid), now).unwrap();
    assert!(result.established.is_none());
    result.reply.unwrap()
}

#[test]
fn readiness_is_authenticated_domain_separated_and_does_not_consume_data_nonces() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = Crypto::new(&aid).unwrap();
    let mut b = Crypto::new(&bid).unwrap();
    let now = Instant::now();
    let third = final_flight(&mut a, &mut b, aid.node_id(), bid.node_id(), now);
    let session = Packet::parse(&third).unwrap().session;
    assert!(!a.has_session(bid.node_id()));
    assert!(a.pending_for(bid.node_id()));
    assert!(a.begin(bid.node_id(), now).unwrap().is_none());
    assert!(a.encrypt_session(session, b"premature").is_err());
    let ready = b
        .receive_handshake(&third, Some(aid.node_id()), now)
        .unwrap()
        .reply
        .unwrap();
    let mut corrupt = ready.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        a.receive_handshake(&corrupt, Some(bid.node_id()), now)
            .is_err()
    );
    assert!(
        a.receive_handshake(&ready, Some(aid.node_id()), now)
            .is_err()
    );
    let mut relabelled = ready.clone();
    relabelled[4] = DATA;
    assert!(a.decrypt(&relabelled, now).is_err());
    assert!(!a.has_session(bid.node_id()));
    assert_eq!(
        a.receive_handshake(&ready, Some(bid.node_id()), now)
            .unwrap()
            .established,
        Some(bid.node_id())
    );
    assert!(
        a.receive_handshake(&ready, Some(bid.node_id()), now)
            .unwrap()
            .established
            .is_none()
    );
    assert!(!a.pending_for(bid.node_id()));
    for sender in [&mut a, &mut b] {
        let peer = if sender.local == aid.node_id() {
            bid.node_id()
        } else {
            aid.node_id()
        };
        let data = sender.encrypt(peer, b"first data nonce").unwrap();
        assert_eq!(Packet::parse(&data).unwrap().number, 0);
    }
    let data = b
        .encrypt(aid.node_id(), b"replay window is intact")
        .unwrap();
    assert_eq!(a.decrypt(&data, now).unwrap().1, b"replay window is intact");
    assert!(a.decrypt(&data, now).is_err());
    a.sessions.get_mut(&session).unwrap().next = READY_NONCE;
    assert!(
        a.encrypt(bid.node_id(), b"must not collide with READY")
            .is_err()
    );
}

#[test]
fn lost_final_flight_and_confirmation_retry_within_original_deadline() {
    for expire in [false, true] {
        let aid = Identity::generate().unwrap();
        let bid = Identity::generate().unwrap();
        let mut a = Crypto::new(&aid).unwrap();
        let mut b = Crypto::new(&bid).unwrap();
        let now = Instant::now();
        let first = final_flight(&mut a, &mut b, aid.node_id(), bid.node_id(), now);
        let proof = b
            .receive_handshake(&first, Some(aid.node_id()), now)
            .unwrap()
            .reply
            .unwrap();
        a.receive_handshake(&proof, Some(bid.node_id()), now)
            .unwrap();
        let old = a.active_session(bid.node_id()).unwrap();
        let started = now + Duration::from_secs(1);
        let one = a.begin(bid.node_id(), started).unwrap().unwrap();
        let two = b
            .receive_handshake(&one, Some(aid.node_id()), started)
            .unwrap()
            .reply
            .unwrap();
        let late = started + Duration::from_secs(7);
        let third = a
            .receive_handshake(&two, Some(bid.node_id()), late)
            .unwrap()
            .reply
            .unwrap();
        let new = Packet::parse(&third).unwrap().session;
        assert_eq!(a.active_session(bid.node_id()), Some(old));
        let retry_at = late + RETRY;
        assert_eq!(a.maintenance(retry_at), [(bid.node_id(), third.clone())]);
        let proof = b
            .receive_handshake(&third, Some(aid.node_id()), retry_at)
            .unwrap()
            .reply
            .unwrap();
        // Lose READY too; re-sent HS3 must return exactly the cached proof.
        assert_eq!(
            a.maintenance(retry_at + RETRY),
            [(bid.node_id(), third.clone())]
        );
        assert_eq!(
            b.receive_handshake(&third, Some(aid.node_id()), retry_at + RETRY)
                .unwrap()
                .reply
                .unwrap(),
            proof
        );
        if expire {
            a.maintenance(started + HANDSHAKE_TTL);
            assert!(!a.contains_session(new));
            assert!(!a.pending_for(bid.node_id()));
            assert_eq!(a.active_session(bid.node_id()), Some(old));
            assert!(
                a.receive_handshake(&proof, Some(bid.node_id()), started + HANDSHAKE_TTL)
                    .is_err()
            );
        } else {
            a.receive_handshake(&proof, Some(bid.node_id()), retry_at + RETRY)
                .unwrap();
            assert_eq!(a.active_session(bid.node_id()), Some(new));
        }
    }
}

#[test]
fn provisional_keys_share_the_global_handshake_limit_and_expire() {
    let aid = Identity::generate().unwrap();
    let mut a = Crypto::new(&aid).unwrap();
    let now = Instant::now();
    for _ in 0..MAX_PENDING {
        let bid = Identity::generate().unwrap();
        let mut b = Crypto::new(&bid).unwrap();
        final_flight(&mut a, &mut b, aid.node_id(), bid.node_id(), now);
    }
    assert_eq!(a.confirming.len(), MAX_PENDING);
    assert_eq!(a.pending.len(), 0);
    assert_eq!(a.sessions.len(), MAX_PENDING);
    let extra = Identity::generate().unwrap();
    assert!(a.begin(extra.node_id(), now).is_err());
    a.maintenance(now + HANDSHAKE_TTL);
    assert!(a.confirming.is_empty() && a.sessions.is_empty() && a.completed.is_empty());
    assert!(
        a.begin(extra.node_id(), now + HANDSHAKE_TTL)
            .unwrap()
            .is_some()
    );
}

#[test]
fn delayed_confirmation_never_rolls_back_a_newer_ready_key() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = Crypto::new(&aid).unwrap();
    let mut b = Crypto::new(&bid).unwrap();
    let now = Instant::now();
    let first = final_flight(&mut a, &mut b, aid.node_id(), bid.node_id(), now);
    // A second explicitly raced candidate is allowed; the ordinary begin() is suppressed.
    let one = a.begin_candidate(bid.node_id(), now).unwrap().unwrap();
    let two = b
        .receive_handshake(&one, Some(aid.node_id()), now)
        .unwrap()
        .reply
        .unwrap();
    let second = a
        .receive_handshake(&two, Some(bid.node_id()), now)
        .unwrap()
        .reply
        .unwrap();
    let early = b
        .receive_handshake(&first, Some(aid.node_id()), now)
        .unwrap()
        .reply
        .unwrap();
    let late = b
        .receive_handshake(&second, Some(aid.node_id()), now)
        .unwrap()
        .reply
        .unwrap();
    let new = Packet::parse(&late).unwrap().session;
    a.receive_handshake(&late, Some(bid.node_id()), now)
        .unwrap();
    a.receive_handshake(&early, Some(bid.node_id()), now)
        .unwrap();
    assert_eq!(a.active_session(bid.node_id()), Some(new));
    let payload = a.encrypt(bid.node_id(), b"chosen key").unwrap();
    assert_eq!(b.decrypt(&payload, now).unwrap().1, b"chosen key");
    let old = Packet::parse(&early).unwrap().session;
    assert!(
        a.contains_session(old),
        "a retained receive key is not a sending rollback"
    );
    let mut legacy = a
        .begin_candidate(Identity::generate().unwrap().node_id(), now)
        .unwrap()
        .unwrap();
    legacy[3] = b'1';
    assert!(
        Packet::parse(&legacy).is_err(),
        "v1 peers must not share v2 nonce semantics"
    );
}

#[test]
fn incoming_session_id_cannot_replace_another_identitys_live_key() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let cid = Identity::generate().unwrap();
    let mut a = Crypto::new(&aid).unwrap();
    let mut b = Crypto::new(&bid).unwrap();
    let mut c = Crypto::new(&cid).unwrap();
    let now = Instant::now();
    let third = final_flight(&mut a, &mut b, aid.node_id(), bid.node_id(), now);
    let ready = b
        .receive_handshake(&third, Some(aid.node_id()), now)
        .unwrap()
        .reply
        .unwrap();
    a.receive_handshake(&ready, Some(bid.node_id()), now)
        .unwrap();
    let victim = b.active_session(aid.node_id()).unwrap();
    let later = now + Duration::from_secs(15);
    b.maintenance(later); // completed-flight cache expires, live key does not.
    assert!(b.contains_session(victim));
    assert!(!b.completed.contains_key(&victim));

    // A session number is visible on the wire, not an identity secret.
    // Construct a fully valid Noise initiation under C's own identity,
    // deliberately choosing A/B's still-live session number.
    let mut noise = c
        .builder(victim, cid.node_id(), bid.node_id(), true)
        .unwrap();
    let mut output = [0; 512];
    let size = noise.write_message(&[], &mut output).unwrap();
    let mut payload = cid.node_id().as_bytes().to_vec();
    payload.extend_from_slice(&output[..size]);
    payload.resize(256, 0);
    let one = wire::session_packet(HS1, wire::LINK_SCOPE, victim, 0, &payload);
    c.pending.insert(
        victim,
        Pending {
            noise,
            peer: bid.node_id(),
            initiator: true,
            last: one.clone(),
            updated: later,
            started: later,
        },
    );
    let pending = b.pending.len();
    let rate = b.recent_inits.len();
    assert!(
        b.receive_handshake(&one, Some(cid.node_id()), later)
            .is_err(),
        "incoming session ID must not replace a live identity-bound key"
    );
    assert_eq!(b.pending.len(), pending);
    assert_eq!(
        b.recent_inits.len(),
        rate,
        "collision does not consume handshake admission"
    );
    assert!(!b.pending.contains_key(&victim));
    assert_eq!(b.sessions[&victim].peer, aid.node_id());
    assert_eq!(b.active_session(cid.node_id()), None);
    let payload = b.encrypt(aid.node_id(), b"victim-only payload").unwrap();
    assert_eq!(
        a.decrypt(&payload, later).unwrap().1,
        b"victim-only payload"
    );
    // Rejecting one colliding ID does not ban the identity: a distinct
    // authenticated session remains admissible and has its own key.
    c.pending.clear();
    let fresh = final_flight(&mut c, &mut b, cid.node_id(), bid.node_id(), later);
    let ready = b
        .receive_handshake(&fresh, Some(cid.node_id()), later)
        .unwrap()
        .reply
        .unwrap();
    c.receive_handshake(&ready, Some(bid.node_id()), later)
        .unwrap();
    assert_ne!(
        b.active_session(aid.node_id()),
        b.active_session(cid.node_id())
    );
    let original = b.encrypt(aid.node_id(), b"original peer").unwrap();
    let other = b.encrypt(cid.node_id(), b"other peer").unwrap();
    assert!(c.decrypt(&original, later).is_err());
    assert!(a.decrypt(&other, later).is_err());
    assert_eq!(a.decrypt(&original, later).unwrap().1, b"original peer");
    assert_eq!(c.decrypt(&other, later).unwrap().1, b"other peer");
}
