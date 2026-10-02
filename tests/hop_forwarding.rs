//! The relay sees one decrypted overlay envelope and re-encrypts for the next
//! neighbor. Real Noise + Link/FEC codecs; no end-to-end key exists between A/B.
use nnlan::{
    identity::{Identity, NodeId},
    reliability::fec::FecScope,
    transport::{
        crypto::Crypto,
        link::{Controller, Link, Message},
        wire::{DATA, Envelope},
    },
};
use std::time::{Duration, Instant};

fn establish(a: &mut Crypto, b: &mut Crypto, aid: NodeId, bid: NodeId, now: Instant) {
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
    assert_eq!(
        a.receive_handshake(&ready, Some(bid), now)
            .unwrap()
            .established,
        Some(bid)
    );
}

fn transfer(
    sender: &mut Crypto,
    receiver: &mut Crypto,
    from: NodeId,
    to: NodeId,
    envelope: &Envelope,
    now: Instant,
) -> Envelope {
    let epoch = sender.active_session(to).unwrap();
    let scope = |peer| FecScope {
        peer,
        path_epoch: epoch,
        key_epoch: epoch,
        direction: 0,
    };
    let mut tx = Link::new(scope(to), now, Default::default());
    let mut rx = Link::new(scope(from), now, Default::default());
    let mut tx_control = Controller::new(10_000_000, now);
    let mut rx_control = Controller::new(10_000_000, now);
    tx.enqueue(
        Message {
            kind: 2,
            payload: envelope.encode(),
        },
        now,
        &tx_control,
    )
    .unwrap();
    for i in 1..100 {
        let at = now + Duration::from_millis(i);
        tx_control.tick(at, tx.stats(&tx_control).queued_bytes, true);
        for plain in tx.poll(at, 32, &mut tx_control).unwrap() {
            let encrypted = sender.encrypt_session(epoch, &plain).unwrap();
            assert!(!encrypted.windows(20).any(|w| w == b"relay-readable-body!"));
            let mut corrupt = encrypted.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(receiver.decrypt(&corrupt, at).is_err());
            let (peer, recovered) = receiver.decrypt(&encrypted, at).unwrap();
            assert_eq!(peer, from);
            assert!(
                receiver.decrypt(&encrypted, at).is_err(),
                "per-hop replay rejected"
            );
            if let Some(message) = rx
                .receive_authenticated(&recovered, at, &mut rx_control)
                .unwrap()
                .into_iter()
                .next()
            {
                assert_eq!(message.kind, 2);
                return Envelope::decode(&message.payload).unwrap();
            }
        }
    }
    panic!("bounded link delivery");
}

#[test]
fn relay_reads_payload_but_each_hop_authenticates_and_rejects_replay() {
    let a = Identity::generate().unwrap();
    let c = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let mut ac = Crypto::new(&a).unwrap();
    let mut cc = Crypto::new(&c).unwrap();
    let mut bc = Crypto::new(&b).unwrap();
    let now = Instant::now();
    establish(&mut ac, &mut cc, a.node_id(), c.node_id(), now);
    establish(&mut cc, &mut bc, c.node_id(), b.node_id(), now);
    assert!(!ac.has_session(b.node_id()) && !bc.has_session(a.node_id()));
    let body = [vec![0], b"relay-readable-body!".repeat(70)].concat();
    let sent = Envelope {
        source: a.node_id(),
        destination: b.node_id(),
        hops: 32,
        kind: DATA,
        body,
    };
    let mut at_relay = transfer(&mut ac, &mut cc, a.node_id(), c.node_id(), &sent, now);
    assert_eq!(at_relay.body, sent.body);
    assert_eq!(at_relay.source, a.node_id());
    at_relay.hops -= 1;
    let received = transfer(&mut cc, &mut bc, c.node_id(), b.node_id(), &at_relay, now);
    assert_eq!(received.body, sent.body);
    assert_eq!(received.source, a.node_id());
    assert_eq!(received.hops, 31);
    assert!(!ac.has_session(b.node_id()) && !bc.has_session(a.node_id()));
}
