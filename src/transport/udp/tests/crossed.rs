use super::*;
use crate::transport::wire::{HS2, HS3, READY};

pub(super) async fn flight(transport: &mut UdpTransport, kind: u8) {
    let mut buffer = [0; MAX_UDP + 1];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let (n, from, local) = tokio::time::timeout_at(deadline, transport.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        if Packet::parse(&buffer[..n]).unwrap().kind == DATA {
            // Initial key confirmation can leave ordinary PMTU/ACK traffic in
            // the socket. Process it without changing the ordered Noise flights.
            transport
                .receive(&buffer[..n], from, local, Instant::now())
                .await;
            continue;
        }
        assert_eq!(Packet::parse(&buffer[..n]).unwrap().kind, kind);
        transport
            .handshake(&buffer[..n], from, local, Instant::now(), &mut vec![])
            .await
            .unwrap();
        break;
    }
}

#[tokio::test]
async fn crossed_rekey_retains_bidirectional_pmtu_and_data() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let previous = a.crypto.active_session(bid.node_id()).unwrap();

    // Both peers can reach the rekey timer together. Deliver the real UDP
    // flights in a controlled order so each finishes as a responder last.
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    b.connect(aid.node_id(), a.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    for kind in [HS1, HS2, HS3, READY] {
        flight(&mut a, kind).await;
        flight(&mut b, kind).await;
    }
    let a_epoch = a.crypto.active_session(bid.node_id()).unwrap();
    let b_epoch = b.crypto.active_session(aid.node_id()).unwrap();
    assert_ne!(a_epoch, previous);
    assert_ne!(b_epoch, previous);
    assert_ne!(a_epoch, b_epoch, "independent outgoing epochs are valid");
    assert!(a.crypto.contains_session(b_epoch) && b.crypto.contains_session(a_epoch));
    assert_eq!(a.status(Instant::now())[0].key_epoch, Some(a_epoch));
    assert_eq!(b.status(Instant::now())[0].key_epoch, Some(b_epoch));

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        step(&mut a).await;
        step(&mut b).await;
        if a.peers[&bid.node_id()].pmtu.limit() == MAX_UDP
            && b.peers[&aid.node_id()].pmtu.limit() == MAX_UDP
        {
            break;
        }
    }
    for state in [
        a.peers[&bid.node_id()].pmtu.status(),
        b.peers[&aid.node_id()].pmtu.status(),
    ] {
        assert!(
            state.confirmed,
            "crossed rekey must not silently discard peer probes"
        );
        assert_eq!(state.udp_payload, MAX_UDP);
    }

    let message = Message {
        kind: 7,
        payload: vec![9; 8192],
    };
    a.send(bid.node_id(), message.clone(), Instant::now())
        .unwrap();
    b.send(aid.node_id(), message.clone(), Instant::now())
        .unwrap();
    let mut delivered = [false; 2];
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !delivered.iter().all(|v| *v) {
        for (i, peer, t) in [(0, bid.node_id(), &mut a), (1, aid.node_id(), &mut b)] {
            for event in step(t).await {
                if let Event::Message(from, received) = event {
                    assert_eq!(from, peer);
                    assert_eq!(received, message);
                    assert!(!delivered[i], "no duplicate message delivery");
                    delivered[i] = true;
                }
            }
        }
    }
    assert_eq!(delivered, [true, true]);
    assert_eq!(a.crypto.active_session(bid.node_id()), Some(a_epoch));
    assert_eq!(b.crypto.active_session(aid.node_id()), Some(b_epoch));
    assert_eq!(a.invalid_packets + b.invalid_packets, 0);
}

#[tokio::test]
async fn same_path_rekey_preserves_mtu_and_queued_old_epoch_payload() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = a.crypto.active_session(bid.node_id()).unwrap();
    let payload = Message {
        kind: 7,
        payload: vec![42; 8192],
    };
    a.send(bid.node_id(), payload.clone(), Instant::now())
        .unwrap();
    assert!(
        a.links[&old]
            .stats(&a.peers[&bid.node_id()].control)
            .queued_data_packets
            > 0
    );
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    flight(&mut b, HS1).await;
    flight(&mut a, HS2).await;
    flight(&mut b, HS3).await;
    flight(&mut a, READY).await;
    let new = a.crypto.active_session(bid.node_id()).unwrap();
    assert_ne!(old, new);
    for state in [a.status(Instant::now()), b.status(Instant::now())] {
        assert_eq!(
            state[0].pmtu.udp_payload, MAX_UDP,
            "keys changed, not the proven path"
        );
        assert!(state[0].pmtu.confirmed);
    }
    let mut deliveries = 0;
    let deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < deadline {
        step(&mut a).await;
        for event in step(&mut b).await {
            if let Event::Message(peer, message) = event {
                assert_eq!(peer, aid.node_id());
                assert_eq!(message, payload);
                deliveries += 1;
            }
        }
        if deliveries == 1
            && a.links[&old]
                .stats(&a.peers[&bid.node_id()].control)
                .in_flight
                == 0
        {
            break;
        }
    }
    assert_eq!(
        deliveries, 1,
        "queued old-epoch sources still deliver exactly once"
    );
    assert_eq!(
        a.links[&old]
            .stats(&a.peers[&bid.node_id()].control)
            .unsent_sources_dropped,
        0
    );
    assert_eq!(
        a.links[&old]
            .stats(&a.peers[&bid.node_id()].control)
            .in_flight,
        0
    );
    assert!(a.links.contains_key(&new) && b.links.contains_key(&new));
}

#[tokio::test]
async fn authenticated_reconnect_from_new_endpoint_resets_mtu() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = b.crypto.active_session(aid.node_id()).unwrap();
    let mut replacement = transport(&aid, 1, vec![bid.node_id()]);
    assert_ne!(replacement.local_addr().unwrap(), a.local_addr().unwrap());
    replacement
        .connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    flight(&mut b, HS1).await;
    flight(&mut replacement, HS2).await;
    flight(&mut b, HS3).await;
    flight(&mut replacement, READY).await;
    assert_ne!(b.crypto.active_session(aid.node_id()), Some(old));
    assert_eq!(
        b.peers[&aid.node_id()].endpoint,
        replacement.local_addr().unwrap()
    );
    let mtu = b.peers[&aid.node_id()].pmtu.status();
    assert_eq!(mtu.udp_payload, crate::transport::link::frame::MIN_UDP);
    assert!(!mtu.confirmed);
    full_mtu(&mut replacement, &mut b, aid.node_id(), bid.node_id()).await;
}

#[tokio::test]
async fn same_path_rekey_keeps_the_learned_bandwidth_and_burst() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = a.crypto.active_session(bid.node_id()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while a.status(Instant::now())[0].link.control.rate_bps <= 8_100_000 {
        a.send(
            bid.node_id(),
            Message {
                kind: 7,
                payload: vec![42; 8192],
            },
            Instant::now(),
        )
        .unwrap();
        step(&mut a).await;
        step(&mut b).await;
        assert!(
            Instant::now() < deadline,
            "warm the actual ACK-driven estimator"
        );
    }
    while a.status(Instant::now())[0].link.in_flight > 0 {
        step(&mut a).await;
        step(&mut b).await;
        assert!(Instant::now() < deadline, "drain the warmup");
    }
    step(&mut a).await;
    step(&mut b).await;
    let before = a.status(Instant::now())[0].link.control.clone();
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    flight(&mut b, HS1).await;
    flight(&mut a, HS2).await;
    flight(&mut b, HS3).await;
    flight(&mut a, READY).await;
    assert_ne!(a.crypto.active_session(bid.node_id()), Some(old));
    let after = a.status(Instant::now())[0].link.control.clone();
    assert_eq!(
        after.rate_bps, before.rate_bps,
        "a key change is not a new congestion path"
    );
    assert_eq!(after.burst_bytes, before.burst_bytes);

    // The same identity from a genuinely new endpoint is NOT the old path.
    let mut replacement = transport(&bid, 1, vec![aid.node_id()]);
    assert_ne!(replacement.local_addr().unwrap(), b.local_addr().unwrap());
    replacement
        .connect(aid.node_id(), a.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    flight(&mut a, HS1).await;
    flight(&mut replacement, HS2).await;
    flight(&mut a, HS3).await;
    flight(&mut replacement, READY).await;
    let migrated = a.status(Instant::now());
    assert_eq!(migrated[0].link.control.rate_bps, 8_100_000);
    assert_eq!(
        migrated[0].pmtu.udp_payload,
        crate::transport::link::frame::MIN_UDP
    );
    assert!(!a.links.contains_key(&old));
}

#[tokio::test]
async fn delayed_final_rekey_flight_keeps_business_on_a_ready_key() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    establish(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
    let old = a.crypto.active_session(bid.node_id()).unwrap();
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    flight(&mut b, HS1).await;
    flight(&mut a, HS2).await;
    let mut buffer = [0; MAX_UDP + 1];
    let (n, from, local) = timeout(Duration::from_secs(1), b.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let held = buffer[..n].to_vec();
    let packet = Packet::parse(&held).unwrap();
    assert_eq!(packet.kind, HS3);
    let new = packet.session;
    assert!(b.crypto.pending_session(new) && !b.crypto.contains_session(new));
    assert!(a.crypto.contains_session(old) && b.crypto.contains_session(old));
    let message = Message {
        kind: 7,
        payload: vec![42; 900],
    };
    a.send(bid.node_id(), message.clone(), Instant::now())
        .unwrap();
    let mut delivered_before_final_flight = 0;
    for _ in 0..10 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if matches!(event, Event::Message(_, ref data) if *data == message) {
                delivered_before_final_flight += 1;
            }
        }
    }
    let rejected = b.invalid_packets;
    // Deliver precisely the held authentic final flight, then verify fixture recovery.
    b.handshake(&held, from, local, Instant::now(), &mut vec![])
        .await
        .unwrap();
    let fresh = Message {
        kind: 8,
        payload: vec![43; 900],
    };
    a.send(bid.node_id(), fresh.clone(), Instant::now())
        .unwrap();
    let mut delivered_after = 0;
    for _ in 0..30 {
        step(&mut a).await;
        for event in step(&mut b).await {
            if matches!(event, Event::Message(_, ref data) if *data == fresh) {
                delivered_after += 1;
            }
        }
        if delivered_after == 1 {
            break;
        }
    }
    println!(
        "before_final={delivered_before_final_flight} after_final={delivered_after} rejected_before_final={rejected}"
    );
    assert_eq!(
        delivered_after, 1,
        "the handshake and business payload are otherwise valid"
    );
    assert_eq!(
        delivered_before_final_flight, 1,
        "keep the old ready key until the new remote key is confirmed"
    );
}

#[tokio::test]
async fn data_overtaking_ready_confirms_only_on_the_pinned_path() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
    a.connect(bid.node_id(), b.local_addr().unwrap(), Instant::now())
        .await
        .unwrap();
    flight(&mut b, HS1).await;
    flight(&mut a, HS2).await;
    assert!(!a.has_peer(bid.node_id()));
    flight(&mut b, HS3).await;
    let mut buffer = [0; MAX_UDP + 1];
    let (n, from, local) = timeout(Duration::from_secs(1), a.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let held = buffer[..n].to_vec();
    assert_eq!(Packet::parse(&held).unwrap().kind, READY);
    let session = Packet::parse(&held).unwrap().session;
    let probe = b
        .peers
        .get_mut(&aid.node_id())
        .unwrap()
        .pmtu
        .poll(Instant::now())
        .unwrap()
        .unwrap();
    let packet = b.crypto.encrypt_session(session, &probe).unwrap();
    // Even authentic DATA cannot consume this nonce or confirm a different path.
    assert!(
        a.handle(
            &packet,
            "127.0.0.1:1".parse().unwrap(),
            local,
            Instant::now(),
            &mut vec![]
        )
        .await
        .is_err()
    );
    assert!(a.crypto.awaiting_confirmation(session));
    let mut events = vec![];
    a.handle(&packet, from, local, Instant::now(), &mut events)
        .await
        .unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Connected(p) if *p == bid.node_id()))
    );
    assert!(a.has_peer(bid.node_id()));
    assert_eq!(a.crypto.active_session(bid.node_id()), Some(session));
    let mut repeated = vec![];
    a.handshake(&held, from, local, Instant::now(), &mut repeated)
        .await
        .unwrap();
    assert!(repeated.is_empty());
    a.send(
        bid.node_id(),
        Message {
            kind: 7,
            payload: vec![8; 900],
        },
        Instant::now(),
    )
    .unwrap();
    let mut delivered = 0;
    for _ in 0..30 {
        step(&mut a).await;
        for e in step(&mut b).await {
            if matches!(e, Event::Message(_, ref m) if m.kind == 7 && m.payload == vec![8; 900]) {
                delivered += 1;
            }
        }
        if delivered == 1 {
            break;
        }
    }
    assert_eq!(delivered, 1);
}
