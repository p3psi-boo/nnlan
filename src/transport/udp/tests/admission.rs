use super::crossed::flight;
use super::*;
use crate::transport::wire::{HS2, HS3, READY};

#[tokio::test]
async fn malformed_first_data_does_not_swallow_admission() {
    // Empty Link frame, truncated PMTU, and truncated path control all fail
    // after AEAD succeeds. None may erase the committed connection event.
    for plain in [&[][..], &[pmtu::TAG][..], &[255][..]] {
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
        let malformed = b.crypto.encrypt_session(session, plain).unwrap();
        let mut corrupted = malformed.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(
            a.receive(&corrupted, from, local, Instant::now())
                .await
                .is_empty()
        );
        assert!(
            !a.has_peer(bid.node_id()),
            "authentication failure never admits a peer"
        );
        assert!(a.crypto.awaiting_confirmation(session));

        let events = a.receive(&malformed, from, local, Instant::now()).await;
        assert!(
            matches!(events.as_slice(), [Event::Connected(p)] if *p == bid.node_id()),
            "authenticated first DATA must not swallow the only admission event"
        );
        assert!(a.has_peer(bid.node_id()));
        assert_eq!(
            a.invalid_packets, 2,
            "both corrupt ciphertext and malformed payload are rejected"
        );
        assert!(
            a.receive(&malformed, from, local, Instant::now())
                .await
                .is_empty()
        );
        assert_eq!(
            a.invalid_packets, 3,
            "rejecting payload syntax does not undo replay protection"
        );
        for _ in 0..2 {
            assert!(
                a.receive(&held, from, local, Instant::now())
                    .await
                    .is_empty()
            );
        }
        assert_eq!(
            a.invalid_packets, 3,
            "late/duplicate READY is valid but does not re-admit"
        );
        assert_eq!(a.crypto.active_session(bid.node_id()), Some(session));
        assert!(a.links.contains_key(&session));
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
            assert!(
                !step(&mut a)
                    .await
                    .iter()
                    .any(|e| matches!(e, Event::Connected(_)))
            );
            for e in step(&mut b).await {
                if matches!(e, Event::Message(_, ref m) if m.kind == 7 && m.payload == vec![8; 900])
                {
                    delivered += 1;
                }
            }
            if delivered == 1 {
                break;
            }
        }
        assert_eq!(
            delivered, 1,
            "valid business still works after rejecting the malformed first payload"
        );
    }
}

#[tokio::test]
async fn failed_ready_send_preserves_admission_and_cached_retry() {
    let aid = Identity::generate().unwrap();
    let bid = Identity::generate().unwrap();
    let mut a = transport(&aid, 1, vec![bid.node_id()]);
    let mut b = transport(&bid, 1, vec![]);
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
    assert_eq!(Packet::parse(&held).unwrap().kind, HS3);
    let session = Packet::parse(&held).unwrap().session;
    // Inject an invalid local destination into the pinned fixture flight. A
    // real kernel send to UDP port zero fails, without a production fault hook.
    let unsendable = "127.0.0.1:0".parse().unwrap();
    let error = b
        .socket
        .send_to(b"send-error probe", unsendable)
        .await
        .unwrap_err();
    assert!(
        !is_path_error(&error),
        "fixture must exercise the fallible send branch"
    );
    b.flights.get_mut(&session).unwrap().endpoint = unsendable;
    let events = b.receive(&held, unsendable, local, Instant::now()).await;
    assert_eq!(b.invalid_packets, 1, "local send failure is still recorded");
    assert!(
        matches!(events.as_slice(), [Event::Connected(p)] if *p == aid.node_id()),
        "send failure must not hide a committed crypto/neighbor transition"
    );
    assert!(b.has_peer(aid.node_id()));
    assert_eq!(b.crypto.active_session(aid.node_id()), Some(session));
    assert!(b.links.contains_key(&session));
    // Remove only the injected send fault. Retransmitting the same genuine HS3
    // must get the cached READY without another Connected or Link replacement.
    b.flights.get_mut(&session).unwrap().endpoint = from;
    b.peers.get_mut(&aid.node_id()).unwrap().endpoint = from;
    let events = b.receive(&held, from, local, Instant::now()).await;
    assert!(events.is_empty());
    assert_eq!(b.invalid_packets, 1);
    let (n, from, local) = timeout(Duration::from_secs(1), a.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Packet::parse(&buffer[..n]).unwrap().kind, READY);
    let events = a.receive(&buffer[..n], from, local, Instant::now()).await;
    assert!(matches!(events.as_slice(), [Event::Connected(p)] if *p == bid.node_id()));
    full_mtu(&mut a, &mut b, aid.node_id(), bid.node_id()).await;
}
