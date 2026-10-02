use super::*;
use nnlan::{
    reliability::fec::FecScope,
    transport::{
        crypto::Crypto,
        link::{Controller, Link},
        wire::{DATA, HS1, HS3, MAX_UDP, Packet},
    },
};

#[test]
fn malformed_first_packet_still_starts_daemon_gossip() {
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    raw.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let remote = Identity::generate().unwrap();
    let local = Identity::generate().unwrap();
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nnlan.toml");
    let log = dir.path().join("daemon.log");
    local.save_new(&dir.path().join("identity.key")).unwrap();
    let mut config = Config {
        name: "admission".into(),
        listen: reservation.local_addr().unwrap(),
        max_neighbors: 1,
        peers: vec![PeerConfig {
            endpoint: raw.local_addr().unwrap().to_string(),
            public_key: remote.node_id(),
        }],
        ..Default::default()
    };
    config.tun.enabled = false;
    config.save(&path).unwrap();
    drop(reservation);
    let binary = std::env::var_os("NNLAN_ADMISSION_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nnlan").into());
    let child = Command::new(binary)
        .args(["--config", path.to_str().unwrap(), "run"])
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    // Own the real process before any fallible handshake/assertion, so failure
    // also reaps it. This fixture deliberately has no second daemon or TUN.
    let mut network = Network {
        _dir: dir,
        paths: vec![path],
        ids: vec![local.node_id()],
        children: vec![child],
        logs: vec![log],
    };
    let mut crypto = Crypto::new(&remote).unwrap();
    let mut buffer = [0; MAX_UDP + 1];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (session, target, ready) = loop {
        assert!(Instant::now() < deadline, "daemon handshake deadline");
        let (n, from) = match raw.recv_from(&mut buffer) {
            Ok(packet) => packet,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => panic!("receive: {e}"),
        };
        let packet = Packet::parse(&buffer[..n]).unwrap();
        assert!(matches!(packet.kind, HS1 | HS3));
        let result = crypto
            .receive_handshake(&buffer[..n], Some(local.node_id()), Instant::now())
            .unwrap();
        let reply = result.reply.unwrap();
        if packet.kind == HS3 {
            assert_eq!(result.established, Some(local.node_id()));
            break (packet.session, from, reply);
        }
        raw.send_to(&reply, from).unwrap();
    };
    // Never send READY yet. Only this authenticated but truncated PMTU packet
    // can establish the initiator's key and trigger Engine's Connected event.
    let malformed = crypto.encrypt_session(session, &[254]).unwrap();
    raw.send_to(&malformed, target).unwrap();
    let now = Instant::now();
    let mut link = Link::new(
        FecScope {
            peer: local.node_id(),
            path_epoch: session,
            key_epoch: session,
            direction: 0,
        },
        now,
        Default::default(),
    );
    let mut control = Controller::new(10_000_000, now);
    let deadline = now + Duration::from_secs(2);
    let mut published = false;
    while Instant::now() < deadline && !published {
        let (n, from) = match raw.recv_from(&mut buffer) {
            Ok(packet) => packet,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => panic!("receive: {e}"),
        };
        assert_eq!(from, target);
        let packet = Packet::parse(&buffer[..n]).unwrap();
        if packet.kind != DATA {
            continue;
        } // Do not answer retries with the held READY.
        let (peer, plain) = crypto.decrypt(&buffer[..n], Instant::now()).unwrap();
        assert_eq!(peer, local.node_id());
        if plain.first().is_some_and(|tag| *tag >= 253) {
            continue;
        }
        for message in link
            .receive_authenticated(&plain, Instant::now(), &mut control)
            .unwrap()
        {
            if message.kind != 1 {
                continue;
            } // Runtime signed-record message.
            let record: Value = serde_json::from_slice(&message.payload).unwrap();
            let descriptor = &record["descriptor"];
            if descriptor["node"] == local.node_id().to_string() {
                assert_eq!(
                    descriptor["neighbors"],
                    serde_json::json!([remote.node_id()])
                );
                published = true;
            }
        }
    }
    assert!(
        published,
        "committed admission must start actual daemon gossip before READY"
    );
    let status = network.call(0, Request::Status).unwrap();
    assert_eq!(status["neighbors"].as_array().unwrap().len(), 1);
    assert_eq!(status["invalid_udp"], 1);
    raw.send_to(&ready, target).unwrap();
    raw.send_to(&ready, target).unwrap();
    network.wait(Duration::from_secs(1), |n| {
        n.call(0, Request::Status)
            .is_some_and(|s| s["network_running"] == true)
    });
}
