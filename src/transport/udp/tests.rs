use super::*;
use tokio::time::timeout;

mod admission;
mod crossed;

fn transport(id: &Identity, limit: usize, configured: Vec<NodeId>) -> UdpTransport {
    UdpTransport::bind(
        id,
        "127.0.0.1:0".parse().unwrap(),
        limit,
        configured,
        10_000_000,
        None,
        Default::default(),
    )
    .unwrap()
}
async fn step(t: &mut UdpTransport) -> Vec<Event> {
    let mut events = t.tick(Instant::now()).await.unwrap();
    let mut buffer = [0; MAX_UDP + 1];
    for _ in 0..64 {
        let Ok(received) = timeout(Duration::from_millis(1), t.recv(&mut buffer)).await else {
            break;
        };
        let (n, from, local) = received.unwrap();
        events.extend(t.receive(&buffer[..n], from, local, Instant::now()).await);
    }
    events
}
async fn establish(a: &mut UdpTransport, b: &mut UdpTransport, aid: NodeId, bid: NodeId) {
    a.connect(bid, b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        step(a).await;
        step(b).await;
        if a.has_peer(bid) && b.has_peer(aid) {
            return;
        }
    }
    panic!("UDP adjacency did not establish");
}

async fn full_mtu(a: &mut UdpTransport, b: &mut UdpTransport, aid: NodeId, bid: NodeId) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        step(a).await;
        step(b).await;
        if a.peers[&bid].pmtu.limit() == MAX_UDP && b.peers[&aid].pmtu.limit() == MAX_UDP {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "both directions must prove full MTU"
        );
    }
    // Drain setup traffic before tests explicitly order handshake flights.
    step(a).await;
    step(b).await;
}

#[tokio::test]
async fn candidate_race_keeps_path_pins_and_cancels_only_after_verification() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead = sink.local_addr().unwrap();
    let live = b.local_addr().unwrap();
    let now = Instant::now();
    a.connect_candidate(bid.node_id(), dead, now).await.unwrap();
    let mut buffer = [0; MAX_UDP + 1];
    let (n, _) = timeout(Duration::from_secs(1), sink.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let first = buffer[..n].to_vec();
    let first_session = Packet::parse(&first).unwrap().session;
    a.connect_candidate(bid.node_id(), dead, now).await.unwrap();
    assert_eq!(
        a.flights.len(),
        1,
        "same candidate must not consume another flight"
    );
    a.connect_candidate(bid.node_id(), live, now).await.unwrap();
    a.connect_candidate(bid.node_id(), "127.0.0.1:1".parse().unwrap(), now)
        .await
        .unwrap();
    assert_eq!(a.flights.len(), 2, "outgoing race must stay bounded");

    step(&mut b).await;
    let (n, from, local) = timeout(Duration::from_secs(1), a.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let reply = buffer[..n].to_vec();
    // Even a valid signed reply cannot move its flight to an unrelated source.
    assert!(
        a.handshake(&reply, dead, local, Instant::now(), &mut vec![])
            .await
            .is_err()
    );
    assert!(!a.has_peer(bid.node_id()));
    assert!(a.crypto.pending_session(first_session));
    a.handshake(&reply, from, local, Instant::now(), &mut vec![])
        .await
        .unwrap();
    step(&mut b).await;
    step(&mut a).await;
    assert!(a.has_peer(bid.node_id()) && b.has_peer(aid.node_id()));
    assert_eq!(a.peers[&bid.node_id()].endpoint, live);
    assert!(!a.crypto.pending_session(first_session));
    assert!(!a.flights.contains_key(&first_session));

    // A late cryptographically valid answer on the losing path stays obsolete.
    let late = b
        .crypto
        .receive_handshake(&first, Some(aid.node_id()), Instant::now())
        .unwrap()
        .reply
        .unwrap();
    assert!(
        a.handshake(&late, dead, None, Instant::now(), &mut vec![])
            .await
            .is_err()
    );
    assert_eq!(a.peers[&bid.node_id()].endpoint, live);
    a.send(
        bid.node_id(),
        Message {
            kind: 4,
            payload: vec![33; 2048],
        },
        Instant::now(),
    )
    .unwrap();
    let mut delivered = false;
    for _ in 0..30 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if let Event::Message(peer, message) = event {
                assert_eq!(peer, aid.node_id());
                assert_eq!(message.payload, vec![33; 2048]);
                delivered = true;
            }
        }
        if delivered {
            break;
        }
    }
    assert!(delivered);
}

#[tokio::test]
async fn wrong_candidate_identity_does_not_cancel_a_delayed_valid_path() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let wrong = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut c = transport(&wrong, 1, vec![]);
    let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = proxy.local_addr().unwrap();
    let now = Instant::now();
    a.connect_candidate(bid.node_id(), endpoint, now)
        .await
        .unwrap();
    let mut buffer = [0; MAX_UDP + 1];
    let (n, _) = timeout(Duration::from_secs(1), proxy.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let first = buffer[..n].to_vec();
    let first_session = Packet::parse(&first).unwrap().session;
    a.connect_candidate(bid.node_id(), c.local_addr().unwrap(), now)
        .await
        .unwrap();
    step(&mut c).await;
    step(&mut a).await;
    assert!(!a.has_peer(bid.node_id()) && !a.has_peer(wrong.node_id()));
    assert!(a.invalid_packets > 0);
    assert!(a.crypto.pending_session(first_session));

    let mut responder = Crypto::new(&bid).unwrap();
    let reply = responder
        .receive_handshake(&first, Some(aid.node_id()), Instant::now())
        .unwrap()
        .reply
        .unwrap();
    proxy
        .send_to(&reply, a.local_addr().unwrap())
        .await
        .unwrap();
    step(&mut a).await;
    assert!(!a.has_peer(bid.node_id()), "wait for remote key readiness");
    let (n, _) = timeout(Duration::from_secs(1), proxy.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let finished = responder
        .receive_handshake(&buffer[..n], Some(aid.node_id()), Instant::now())
        .unwrap();
    assert_eq!(finished.established, Some(aid.node_id()));
    proxy
        .send_to(&finished.reply.unwrap(), a.local_addr().unwrap())
        .await
        .unwrap();
    step(&mut a).await;
    assert!(a.has_peer(bid.node_id()));
    assert_eq!(a.peers[&bid.node_id()].endpoint, endpoint);
    assert!(!a.crypto.pending_for(bid.node_id()));
}

#[tokio::test]
async fn unilateral_pinning_admission_messages_and_dead_peer_cleanup() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let message = Message {
        kind: 4,
        payload: vec![19; 3000],
    };
    a.send(bid.node_id(), message.clone(), Instant::now())
        .unwrap();
    let mut received = vec![];
    for _ in 0..30 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if let Event::Message(peer, data) = event {
                assert_eq!(peer, aid.node_id());
                received.push(data);
            }
        }
        if !received.is_empty() {
            break;
        }
    }
    assert_eq!(received, [message]);
    assert_eq!(a.connected().count(), 1);
    assert_eq!(b.connected().count(), 1);
    let events = a
        .tick(Instant::now() + DEAD_AFTER + Duration::from_secs(1))
        .await
        .unwrap();
    assert!(matches!(events.as_slice(), [Event::Disconnected(peer)] if *peer == bid.node_id()));
    assert_eq!(a.connected().count(), 0);
    assert!(a.links.is_empty());
}

#[tokio::test]
async fn local_denial_clears_epochs_and_rejects_both_handshake_directions() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    a.set_denied([bid.node_id()].into());
    assert!(!a.has_peer(bid.node_id()) && a.links.is_empty() && a.flights.is_empty());
    assert!(!a.crypto.has_session(bid.node_id()));
    assert!(
        a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
            .await
            .is_err()
    );
    b.disconnect(aid.node_id());
    b.connect(aid.node_id(), a.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    for _ in 0..5 {
        step(&mut b).await;
        step(&mut a).await;
    }
    assert!(!a.has_peer(bid.node_id()) && a.flights.is_empty());
    assert!(a.invalid_packets > 0);
    b.disconnect(aid.node_id());
    a.set_denied(BTreeSet::new());
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
}

#[tokio::test]
async fn configured_peer_slot_is_reserved_during_incoming_handshakes() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let cid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    let mut c = transport(&cid, 1, vec![]);
    c.connect(aid.node_id(), a.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    for _ in 0..5 {
        step(&mut a).await;
        step(&mut c).await;
    }
    assert!(!a.has_peer(cid.node_id()));
    assert!(!c.has_peer(aid.node_id()));
    assert!(a.invalid_packets > 0);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    assert_eq!(a.connected().count(), 1);
}

#[tokio::test]
async fn endpoint_migration_requires_challenge_then_fresh_key_epoch() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let policy = RepairConfig {
        fec: false,
        rtx: false,
    };
    let mut a = UdpTransport::bind(
        &aid,
        "127.0.0.1:0".parse().unwrap(),
        2,
        [],
        10_000_000,
        None,
        policy,
    )
    .unwrap();
    let mut b = transport(&bid, 2, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old_address = a.local_addr().unwrap();
    let old_session = b.crypto.active_session(aid.node_id()).unwrap();
    // Rebind the actual UDP socket while retaining the cryptographic identity/session.
    a.socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let new_address = a.local_addr().unwrap();
    assert_ne!(new_address, old_address);
    a.send(
        bid.node_id(),
        Message {
            kind: 4,
            payload: b"trigger path validation".to_vec(),
        },
        Instant::now(),
    )
    .unwrap();
    step(&mut a).await;
    step(&mut b).await;
    assert_eq!(b.peers[&aid.node_id()].endpoint, old_address);
    assert!(b.challenges.contains_key(&aid.node_id()));
    let mut migrated = false;
    for _ in 0..30 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if matches!(event, Event::EndpointChanged(peer, addr) if peer == aid.node_id() && addr == new_address)
            {
                migrated = true;
                let mtu = b.peers[&aid.node_id()].pmtu.status();
                assert_eq!(mtu.udp_payload, crate::transport::link::frame::MIN_UDP);
                assert!(!mtu.confirmed, "a changed path needs a new proof");
            }
        }
        if b.crypto.active_session(aid.node_id()) != Some(old_session)
            && a.crypto.active_session(bid.node_id()) == b.crypto.active_session(aid.node_id())
        {
            break;
        }
    }
    assert!(migrated);
    assert_eq!(b.peers[&aid.node_id()].endpoint, new_address);
    assert_ne!(b.crypto.active_session(aid.node_id()), Some(old_session));
    assert!(!b.links.contains_key(&old_session));
    let message = Message {
        kind: 5,
        payload: b"after migration".to_vec(),
    };
    a.send(bid.node_id(), message.clone(), Instant::now())
        .unwrap();
    let mut received = vec![];
    for _ in 0..30 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if let Event::Message(_, data) = event {
                received.push(data);
            }
        }
        if !received.is_empty() {
            break;
        }
    }
    assert_eq!(received, [message]);
    assert!(
        a.links
            .values()
            .all(|link| link.stats(&a.peers[&bid.node_id()].control).repair == policy)
    );
    assert!(
        b.links
            .values()
            .all(|link| link.stats(&b.peers[&aid.node_id()].control).repair
                == RepairConfig::default())
    );
    assert!(
        a.links.values().all(
            |link| link.stats(&a.peers[&bid.node_id()].control).fec_sent == 0
                && link.stats(&a.peers[&bid.node_id()].control).retransmitted == 0
        )
    );
}

#[tokio::test]
async fn dual_stack_listener_accepts_ipv4_peer_without_endpoint_mismatch() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = UdpTransport::bind(
        &aid,
        "[::]:0".parse().unwrap(),
        2,
        [],
        10_000_000,
        None,
        Default::default(),
    )
    .unwrap();
    let mut b = transport(&bid, 2, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let message = Message {
        kind: 7,
        payload: b"dual stack".to_vec(),
    };
    a.send(bid.node_id(), message.clone(), Instant::now())
        .unwrap();
    let mut received = vec![];
    for _ in 0..30 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if let Event::Message(_, data) = event {
                received.push(data);
            }
        }
        if !received.is_empty() {
            break;
        }
    }
    assert_eq!(received, [message]);
}

#[tokio::test]
async fn only_current_epoch_observations_reach_candidate_discovery() {
    use crate::transport::link::frame::{Fragment, Frame};
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 2, vec![]);
    let mut b = transport(&bid, 2, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = a.crypto.active_session(bid.node_id()).unwrap();
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    for _ in 0..50 {
        step(&mut a).await;
        step(&mut b).await;
        if a.crypto.active_session(bid.node_id()) != Some(old)
            && a.crypto.active_session(bid.node_id()) == b.crypto.active_session(aid.node_id())
        {
            break;
        }
    }
    let current = a.crypto.active_session(bid.node_id()).unwrap();
    assert_ne!(current, old);
    assert_eq!(b.crypto.active_session(aid.node_id()), Some(current));
    let payload = b"\x01198.18.0.1:40000";
    let frame = Frame::Source {
        group: 1,
        index: 0,
        sent_us: 1,
        retransmitted: false,
        shard: Fragment {
            sequence: 1,
            message: 1,
            index: 0,
            count: 1,
            kind: INTERNAL,
            payload,
        }
        .encode(),
    }
    .encode();
    let invalid = b.invalid_packets;
    let bytes = a.crypto.encrypt_session(old, &frame).unwrap();
    let events = b
        .receive(&bytes, a.local_addr().unwrap(), None, Instant::now())
        .await;
    assert_eq!(b.invalid_packets, invalid);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::ObservedEndpoint { .. }))
    );
    let bytes = a.crypto.encrypt_session(current, &frame).unwrap();
    let events = b
        .receive(&bytes, a.local_addr().unwrap(), None, Instant::now())
        .await;
    assert!(events.iter().any(|e| matches!(e, Event::ObservedEndpoint { observer, address }
        if *observer == aid.node_id() && *address == "198.18.0.1:40000".parse::<SocketAddr>().unwrap())));
}

#[tokio::test]
async fn pmtu_ack_requires_current_epoch_and_validated_endpoint() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 2, vec![]);
    let mut b = transport(&bid, 2, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = a.crypto.active_session(bid.node_id()).unwrap();
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    for _ in 0..50 {
        step(&mut a).await;
        step(&mut b).await;
        if a.crypto.active_session(bid.node_id()) != Some(old)
            && a.crypto.active_session(bid.node_id()) == b.crypto.active_session(aid.node_id())
        {
            break;
        }
    }
    let current = a.crypto.active_session(bid.node_id()).unwrap();
    assert_ne!(current, old);
    let now = Instant::now();
    a.peers.get_mut(&bid.node_id()).unwrap().pmtu = pmtu::PathMtu::new(now);
    let probe = a
        .peers
        .get_mut(&bid.node_id())
        .unwrap()
        .pmtu
        .poll(now)
        .unwrap()
        .unwrap();
    let pmtu::Control::Probe { reply } = pmtu::Control::decode(&probe).unwrap() else {
        panic!()
    };
    let old_reply = b.crypto.encrypt_session(old, &reply).unwrap();
    a.receive(&old_reply, b.local_addr().unwrap(), None, now)
        .await;
    assert!(!a.peers[&bid.node_id()].pmtu.status().confirmed);
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wrong_path_reply = b.crypto.encrypt_session(current, &reply).unwrap();
    a.receive(&wrong_path_reply, other.local_addr().unwrap(), None, now)
        .await;
    assert!(!a.peers[&bid.node_id()].pmtu.status().confirmed);
    let valid_reply = b.crypto.encrypt_session(current, &reply).unwrap();
    a.receive(&valid_reply, b.local_addr().unwrap(), None, now)
        .await;
    assert!(a.peers[&bid.node_id()].pmtu.status().confirmed);
}

#[tokio::test]
async fn both_socket_families_disable_ip_fragmentation_for_probes() {
    use rustix::net::sockopt;
    let identity = Identity::generate().unwrap();
    for listen in ["127.0.0.1:0", "[::]:0"] {
        let t = UdpTransport::bind(
            &identity,
            listen.parse().unwrap(),
            1,
            [],
            10_000_000,
            None,
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            sockopt::ip_mtu_discover(&t.socket).unwrap(),
            sockopt::Ipv4PathMtuDiscovery::PROBE
        );
        if listen.starts_with('[') {
            assert_eq!(
                sockopt::ipv6_mtu_discover(&t.socket).unwrap(),
                sockopt::Ipv6PathMtuDiscovery::PROBE
            );
        }
    }
}

#[tokio::test]
async fn idle_accounting_ignores_housekeeping_and_retirement_reclaims_resources() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 2, vec![]);
    let mut b = transport(&bid, 2, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let idle = Duration::from_secs(60);
    let now = Instant::now();
    a.used(bid.node_id(), now);
    assert!(
        a.retire_idle(bid.node_id(), idle, now)
            .await
            .unwrap()
            .is_none()
    );
    let old = a.crypto.active_session(bid.node_id()).unwrap();
    a.connect(bid.node_id(), b.local_addr().unwrap(), now)
        .await
        .unwrap();
    for _ in 0..50 {
        step(&mut a).await;
        step(&mut b).await;
        if a.crypto.active_session(bid.node_id()) != Some(old)
            && a.crypto.active_session(bid.node_id()) == b.crypto.active_session(aid.node_id())
        {
            break;
        }
    }
    assert_ne!(a.crypto.active_session(bid.node_id()), Some(old));
    assert_eq!(
        a.peers[&bid.node_id()].used,
        now,
        "rekey/keepalive/PMTU must not refresh application idleness"
    );
    assert_eq!(a.idle_candidates(now + idle, idle), [bid.node_id()]);
    assert!(matches!(
        a.retire_idle(bid.node_id(), idle, now + idle)
            .await
            .unwrap(),
        Some(Event::Disconnected(_))
    ));
    assert!(
        a.peers.is_empty() && a.links.is_empty() && a.flights.is_empty() && a.challenges.is_empty()
    );
    assert_eq!(a.idle_retired, 1);
    for _ in 0..10 {
        step(&mut b).await;
        if !b.has_peer(aid.node_id()) {
            break;
        }
    }
    assert!(!b.has_peer(aid.node_id()));
    assert!(b.links.is_empty() && b.flights.is_empty());
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    assert!(a.has_peer(bid.node_id()));
}

#[tokio::test]
async fn configured_neighbors_are_not_idle_candidates_and_old_close_cannot_kill_new_epoch() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 2, vec![bid.node_id()]);
    let mut b = transport(&bid, 2, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = b.crypto.active_session(aid.node_id()).unwrap();
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    for _ in 0..50 {
        step(&mut a).await;
        step(&mut b).await;
        if a.crypto.active_session(bid.node_id()) != Some(old)
            && a.crypto.active_session(bid.node_id()) == b.crypto.active_session(aid.node_id())
        {
            break;
        }
    }
    assert_ne!(a.crypto.active_session(bid.node_id()), Some(old));
    let notice = b.crypto.encrypt_session(old, &[RETIRE]).unwrap();
    a.receive(&notice, b.local_addr().unwrap(), None, Instant::now())
        .await;
    assert!(a.has_peer(bid.node_id()));
    let future = Instant::now() + Duration::from_secs(61);
    assert!(
        a.idle_candidates(future, Duration::from_secs(60))
            .is_empty()
    );
    assert!(
        a.retire_idle(bid.node_id(), Duration::from_secs(60), future)
            .await
            .unwrap()
            .is_none()
    );
    assert!(a.has_peer(bid.node_id()));
}

#[tokio::test]
async fn wildcard_reply_source_ipv4_alias_mapped_and_native_ipv6() {
    for (listen, target_ip, client_bind) in [
        ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "127.0.0.2", "127.0.0.1:0"),
        ("[::]:0", "::1", "[::1]:0"),
    ] {
        let aid = Identity::generate().unwrap();
        let bid = Identity::generate().unwrap();
        let mut a = UdpTransport::bind(
            &aid,
            client_bind.parse().unwrap(),
            1,
            [bid.node_id()],
            10_000_000,
            None,
            Default::default(),
        )
        .unwrap();
        let mut b = UdpTransport::bind(
            &bid,
            listen.parse().unwrap(),
            1,
            [],
            10_000_000,
            None,
            Default::default(),
        )
        .unwrap();
        let target = SocketAddr::new(target_ip.parse().unwrap(), b.local_addr().unwrap().port());
        a.connect(bid.node_id(), target, Instant::now())
            .await
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !(a.has_peer(bid.node_id()) && b.has_peer(aid.node_id())) {
            assert!(
                Instant::now() < deadline,
                "wildcard handshake: {listen} {target}"
            );
            step(&mut a).await;
            step(&mut b).await;
        }
        assert_eq!(a.peers[&bid.node_id()].endpoint, target);
        assert!(b.peers[&aid.node_id()].local.is_some());
        b.send(
            aid.node_id(),
            Message {
                kind: 4,
                payload: vec![7; 4096],
            },
            Instant::now(),
        )
        .unwrap();
        let mut delivered = false;
        while Instant::now() < deadline && !delivered {
            step(&mut b).await;
            delivered |= step(&mut a).await.into_iter().any(|e| matches!(e, Event::Message(_, Message {kind:4,payload}) if payload == vec![7;4096]));
        }
        assert!(delivered, "wildcard data source: {listen}");
        if target.is_ipv4() {
            // An unauthenticated datagram from the real peer's socket to another
            // local alias must not poison the admitted source affinity.
            let before = b.peers[&aid.node_id()].local;
            a.socket
                .send_to(
                    b"not authenticated",
                    SocketAddr::new("127.0.0.3".parse().unwrap(), target.port()),
                )
                .await
                .unwrap();
            step(&mut b).await;
            assert_eq!(b.peers[&aid.node_id()].local, before);
        }
    }
}

#[tokio::test]
async fn io_driven_flush_never_refills_without_elapsed_time() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    a.discard_queued();
    let now = Instant::now();
    a.tokens = 0.0;
    a.updated = now;
    a.send(
        bid.node_id(),
        Message {
            kind: 1,
            payload: vec![1; 16000],
        },
        now,
    )
    .unwrap();
    let before = a.status(now)[0].link.tx_packets;
    for _ in 0..20 {
        a.flush(now).await.unwrap();
    }
    assert_eq!(a.status(now)[0].link.tx_packets, before);
    let later = now + Duration::from_millis(2);
    a.flush(later).await.unwrap();
    let emitted = a.status(later)[0].link.tx_packets;
    assert!(emitted > before);
    for _ in 0..20 {
        a.flush(later).await.unwrap();
    }
    assert_eq!(a.status(later)[0].link.tx_packets, emitted);
    assert!(a.tokens >= 0.0);
    assert_eq!(a.socket_dropped, 0);
}

#[tokio::test]
async fn compact_capability_is_authenticated_and_epoch_local() {
    let ai = Identity::generate().unwrap();
    let bi = Identity::generate().unwrap();
    let aid = ai.node_id();
    let bid = bi.node_id();
    let mut a = transport(&ai, 1, vec![bid]);
    let mut b = transport(&bi, 1, vec![]);
    establish(&mut a, &mut b, aid, bid).await;
    assert!(!a.supports_compact(bid));
    assert!(!b.supports_compact(aid));
    // Unknown capability versions are ignored, even from an authenticated peer.
    a.enqueue(
        bid,
        Message {
            kind: INTERNAL,
            payload: vec![2, 255],
        },
        Instant::now(),
    )
    .unwrap();
    for _ in 0..5 {
        step(&mut a).await;
        step(&mut b).await;
    }
    assert!(!b.supports_compact(aid));
    // An unauthenticated datagram cannot advertise capabilities.
    let fake = wire::session_packet(
        DATA,
        LINK_SCOPE,
        a.crypto.active_session(bid).unwrap(),
        123,
        &[2, 1],
    );
    a.receive(&fake, b.local_addr().unwrap(), None, Instant::now())
        .await;
    assert!(!a.supports_compact(bid));
    let deadline = Instant::now() + Duration::from_secs(3);
    while !a.supports_compact(bid) || !b.supports_compact(aid) {
        step(&mut a).await;
        step(&mut b).await;
        assert!(Instant::now() < deadline, "capability must converge");
    }
    let old = a.crypto.active_session(bid).unwrap();
    a.connect(bid, b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while a.crypto.active_session(bid) == Some(old) {
        step(&mut a).await;
        step(&mut b).await;
        assert!(Instant::now() < deadline);
    }
    assert!(
        !a.supports_compact(bid),
        "a new key epoch starts in the legacy format"
    );
    assert!(
        a.links[&old].supports_compact(),
        "retained keys have independent capability state"
    );
}
