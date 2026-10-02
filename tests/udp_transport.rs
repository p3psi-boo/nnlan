//! Real localhost UDP and Noise, with a userspace datagram fault injector.
//! No TUN/root privileges, no network simulation substituted for encryption or I/O.
use nnlan::{
    identity::Identity,
    reliability::fec::FecScope,
    transport::{
        crypto::Crypto,
        link::{Link, Message, frame::Frame},
        wire::MAX_UDP,
    },
};
use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

fn socket() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}
fn receive(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut out = [0; MAX_UDP];
    let (n, from) = socket.recv_from(&mut out).unwrap();
    (out[..n].to_vec(), from)
}
fn send(socket: &UdpSocket, target: &UdpSocket, bytes: &[u8]) {
    assert!(bytes.len() <= MAX_UDP);
    socket.send_to(bytes, target.local_addr().unwrap()).unwrap();
}

#[test]
fn encrypted_udp_fec_reordering_replay_and_feedback() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let mut ac = Crypto::new(&a).unwrap();
    let mut bc = Crypto::new(&b).unwrap();
    let sa = socket();
    let sb = socket();
    let proxy = socket();
    let now = Instant::now();
    send(&sa, &sb, &ac.begin(b.node_id(), now).unwrap().unwrap());
    let first = receive(&sb).0;
    let second = bc
        .receive_handshake(&first, None, Instant::now())
        .unwrap()
        .reply
        .unwrap();
    send(&sb, &sa, &second);
    let third = ac
        .receive_handshake(&receive(&sa).0, Some(b.node_id()), Instant::now())
        .unwrap()
        .reply
        .unwrap();
    // Lose flight 3, then exercise responder retry and initiator's cached completion.
    send(&sb, &sa, &second);
    assert_eq!(
        ac.receive_handshake(&receive(&sa).0, Some(b.node_id()), Instant::now())
            .unwrap()
            .reply
            .unwrap(),
        third
    );
    send(&sa, &sb, &third);
    let result = bc
        .receive_handshake(&receive(&sb).0, Some(a.node_id()), Instant::now())
        .unwrap();
    assert_eq!(result.established, Some(a.node_id()));
    send(&sb, &sa, &result.reply.unwrap());
    assert_eq!(
        ac.receive_handshake(&receive(&sa).0, Some(b.node_id()), Instant::now())
            .unwrap()
            .established,
        Some(b.node_id())
    );

    let scope = |peer| FecScope {
        peer,
        path_epoch: 0,
        key_epoch: 0,
        direction: 0,
    };
    let mut ac_path = nnlan::transport::link::Controller::new(10_000_000, now);
    let mut bc_path = nnlan::transport::link::Controller::new(10_000_000, now);
    let mut al = Link::new(scope(b.node_id()), now, Default::default());
    let mut bl = Link::new(scope(a.node_id()), now, Default::default());
    let message = Message {
        kind: 2,
        payload: (0..24_000).map(|n| (n % 251) as u8).collect(),
    };
    al.enqueue(message.clone(), Instant::now(), &ac_path)
        .unwrap();
    let mut delivered = vec![];
    let mut dropped = 0;
    let mut replay_tested = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let mut queued = vec![];
        let a_load = al.stats(&ac_path);
        ac_path.tick(Instant::now(), a_load.queued_bytes, a_load.in_flight > 0);
        for plaintext in al.poll(Instant::now(), 64, &mut ac_path).unwrap() {
            let should_drop = matches!(
                Frame::decode(&plaintext).unwrap(),
                Frame::Source {
                    index: 0,
                    retransmitted: false,
                    ..
                }
            );
            let ciphertext = ac.encrypt(b.node_id(), &plaintext).unwrap();
            send(&sa, &proxy, &ciphertext);
            let wire = receive(&proxy).0;
            if should_drop {
                dropped += 1;
            } else {
                queued.push(wire);
            }
        }
        queued.reverse();
        for wire in queued {
            send(&proxy, &sb, &wire);
            let authenticated = bc.decrypt(&receive(&sb).0, Instant::now()).unwrap();
            assert_eq!(authenticated.0, a.node_id());
            delivered.extend(
                bl.receive_authenticated(&authenticated.1, Instant::now(), &mut bc_path)
                    .unwrap(),
            );
            if !replay_tested {
                send(&proxy, &sb, &wire);
                assert!(bc.decrypt(&receive(&sb).0, Instant::now()).is_err());
                replay_tested = true;
            }
        }
        let b_load = bl.stats(&bc_path);
        bc_path.tick(Instant::now(), b_load.queued_bytes, b_load.in_flight > 0);
        for plaintext in bl.poll(Instant::now(), 64, &mut bc_path).unwrap() {
            send(&sb, &sa, &bc.encrypt(a.node_id(), &plaintext).unwrap());
            let authenticated = ac.decrypt(&receive(&sa).0, Instant::now()).unwrap();
            al.receive_authenticated(&authenticated.1, Instant::now(), &mut ac_path)
                .unwrap();
        }
        if delivered.len() == 1 && al.stats(&ac_path).in_flight == 0 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(delivered, [message]);
    assert!(dropped >= 3 && replay_tested);
    assert_eq!(bl.stats(&bc_path).fec_recovered, dropped);
    assert_eq!(al.stats(&ac_path).peer_fec_recovered, dropped);
    assert_eq!(al.stats(&ac_path).retransmitted, 0);
    assert_eq!(al.stats(&ac_path).in_flight, 0);
}

#[test]
fn udp_peer_with_wrong_pinned_key_never_establishes() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    let impostor = Identity::generate().unwrap();
    let mut ac = Crypto::new(&a).unwrap();
    let mut attacker = Crypto::new(&impostor).unwrap();
    let sa = socket();
    let sb = socket();
    let now = Instant::now();
    send(&sa, &sb, &ac.begin(b.node_id(), now).unwrap().unwrap());
    let reply = attacker
        .receive_handshake(&receive(&sb).0, None, now)
        .unwrap()
        .reply
        .unwrap();
    send(&sb, &sa, &reply);
    assert!(
        ac.receive_handshake(&receive(&sa).0, Some(b.node_id()), now)
            .is_err()
    );
    assert!(!ac.has_session(b.node_id()));
    assert!(!attacker.has_session(a.node_id()));
}
