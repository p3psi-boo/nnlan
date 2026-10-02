//! Independent daemon processes and owner-only CLI RPC, not an in-memory topology.
use nnlan::{
    config::{Config, PeerConfig},
    identity::{Identity, NodeId},
    runtime::admin::{Request, socket_path},
};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::UdpSocket,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Network {
    _dir: tempfile::TempDir,
    paths: Vec<PathBuf>,
    ids: Vec<NodeId>,
    children: Vec<Child>,
    logs: Vec<PathBuf>,
}
impl Network {
    fn start(names: &[&str], peers: &[Vec<usize>], limits: &[usize]) -> Self {
        let identities: Vec<_> = names
            .iter()
            .map(|_| Identity::generate().unwrap())
            .collect();
        Self::start_with_identities(names, peers, limits, identities)
    }
    fn start_with_identities(
        names: &[&str],
        peers: &[Vec<usize>],
        limits: &[usize],
        identities: Vec<Identity>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sockets: Vec<_> = names
            .iter()
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let addresses: Vec<_> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
        let mut paths = vec![];
        let mut logs = vec![];
        for (index, name) in names.iter().enumerate() {
            let parent = dir.path().join(name);
            fs::create_dir(&parent).unwrap();
            let path = parent.join("nnlan.toml");
            identities[index]
                .save_new(&parent.join("identity.key"))
                .unwrap();
            let mut config = Config {
                name: (*name).into(),
                listen: addresses[index],
                max_neighbors: limits[index],
                peers: peers[index]
                    .iter()
                    .map(|&p| PeerConfig {
                        endpoint: addresses[p].to_string(),
                        public_key: identities[p].node_id(),
                    })
                    .collect(),
                ..Default::default()
            };
            config.tun.enabled = false;
            config.save(&path).unwrap();
            paths.push(path);
            logs.push(parent.join("daemon.log"));
        }
        drop(sockets);
        let children = paths
            .iter()
            .zip(&logs)
            .map(|(path, log)| {
                Command::new(env!("CARGO_BIN_EXE_nnlan"))
                    .args(["--config", path.to_str().unwrap(), "run"])
                    .stdout(Stdio::null())
                    .stderr(fs::File::create(log).unwrap())
                    .spawn()
                    .unwrap()
            })
            .collect();
        let mut network = Self {
            _dir: dir,
            paths,
            ids: identities.iter().map(Identity::node_id).collect(),
            children,
            logs,
        };
        network.wait(Duration::from_secs(15), |network| {
            (0..names.len()).all(|i| {
                network.call(i, Request::Status).is_some_and(|s| {
                    s["nodes"].as_u64() == Some(names.len() as u64)
                        && s["addresses_claimed"] == true
                })
            })
        });
        network
    }
    fn call(&self, node: usize, request: Request) -> Option<Value> {
        let mut stream = UnixStream::connect(socket_path(&self.paths[node])).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(6))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(6)))
            .ok()?;
        let bytes = serde_json::to_vec(&request).ok()?;
        stream.write_all(&(bytes.len() as u32).to_be_bytes()).ok()?;
        stream.write_all(&bytes).ok()?;
        let mut size = [0; 4];
        stream.read_exact(&mut size).ok()?;
        let size = u32::from_be_bytes(size) as usize;
        if size > 4 * 1024 * 1024 {
            return None;
        }
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
    fn wait(&mut self, duration: Duration, mut condition: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            for (i, child) in self.children.iter_mut().enumerate() {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "daemon {i}: {}",
                    fs::read_to_string(&self.logs[i]).unwrap()
                );
            }
            if condition(self) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "network did not converge: {:?}",
            self.logs
                .iter()
                .map(|p| fs::read_to_string(p).unwrap())
                .collect::<Vec<_>>()
        );
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn four_daemons_transitive_membership_real_trace_and_hop_encryption() {
    let network = Network::start(
        &["a", "c", "d", "b"],
        &[vec![1], vec![2], vec![3], vec![]],
        &[1, 2, 2, 1],
    );
    let trace = network
        .call(0, Request::Trace { target: "b".into() })
        .unwrap();
    assert_eq!(trace["complete"], true, "{trace}");
    let hops: Vec<_> = trace["hops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["node"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        hops,
        network.ids[1..]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    let ping = network
        .call(
            0,
            Request::Ping {
                target: "b".into(),
                size: 16_384,
            },
        )
        .unwrap();
    assert_eq!(ping["hop_encrypted"], true, "{ping}");
    assert!(ping.get("end_to_end_encrypted").is_none());
    assert_eq!(ping["bytes"], 16_384);
    for relay in [1, 2] {
        let status = network.call(relay, Request::Status).unwrap();
        assert_eq!(status["wire_protocol"], "GGB3");
        assert_eq!(status["encryption"], "hop-by-hop");
        assert!(status["forwarded"].as_u64().unwrap() > 0);
        assert_eq!(status["neighbors"].as_array().unwrap().len(), 2);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_nnlan"))
        .args(["--config", network.paths[0].to_str().unwrap(), "status"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["network_running"],
        true
    );
}

#[test]
fn traffic_creates_a_bounded_direct_upgrade_not_a_full_mesh() {
    let mut network = Network::start(&["a", "c", "b"], &[vec![1], vec![], vec![1]], &[2, 2, 2]);
    let before = network
        .call(0, Request::Trace { target: "b".into() })
        .unwrap();
    assert_eq!(before["hops"].as_array().unwrap().len(), 2, "{before}");
    let ping = network
        .call(
            0,
            Request::Ping {
                target: "b".into(),
                size: 512,
            },
        )
        .unwrap();
    assert_eq!(ping["hop_encrypted"], true, "{ping}");
    network.wait(Duration::from_secs(12), |n| {
        n.call(0, Request::Status)
            .is_some_and(|s| s["neighbors"].as_array().unwrap().len() == 2)
            && n.call(2, Request::Status)
                .is_some_and(|s| s["neighbors"].as_array().unwrap().len() == 2)
    });
    let after = network
        .call(0, Request::Trace { target: "b".into() })
        .unwrap();
    assert_eq!(after["complete"], true, "{after}");
    assert_eq!(after["hops"].as_array().unwrap().len(), 1, "{after}");
}

#[test]
fn persistent_local_denial_overrides_transitive_membership_and_survives_restart() {
    use nnlan::runtime::admin::MemberAction;
    let mut n = Network::start(
        &["a", "c", "d", "b"],
        &[vec![1, 2], vec![3], vec![3], vec![]],
        &[2, 2, 2, 2],
    );
    let boot = n.call(0, Request::Status).unwrap()["boot_id"].clone();
    let membership = |n: &Network, deny: bool, index: usize| {
        let node = n.ids[index];
        n.call(
            0,
            Request::Member {
                action: if deny {
                    MemberAction::Deny { node }
                } else {
                    MemberAction::Allow { node }
                },
            },
        )
        .unwrap()
    };
    let ping = |n: &Network| {
        n.call(
            0,
            Request::Ping {
                target: n.ids[3].to_string(),
                size: 4096,
            },
        )
        .unwrap()
    };
    assert_eq!(ping(&n)["hop_encrypted"], true);
    // A learns revocation through newer signed adjacency, not a local command.
    for issuer in [1, 2] {
        let response = n
            .call(
                issuer,
                Request::Member {
                    action: MemberAction::Deny { node: n.ids[3] },
                },
            )
            .unwrap();
        assert!(response.get("error").is_none(), "{response}");
    }
    n.wait(Duration::from_secs(15), |n| {
        n.call(0, Request::Members).is_some_and(|s| {
            !s["trusted"]
                .as_array()
                .unwrap()
                .contains(&Value::String(n.ids[3].to_string()))
        })
    });
    assert!(ping(&n)["error"].is_string());
    for issuer in [1, 2] {
        n.call(
            issuer,
            Request::Member {
                action: MemberAction::Allow { node: n.ids[3] },
            },
        )
        .unwrap();
    }
    n.wait(Duration::from_secs(18), |n| {
        ping(n)["hop_encrypted"] == true
    });
    assert!(membership(&n, true, 0)["error"].is_string());
    let denied = membership(&n, true, 1);
    assert!(
        denied["denied"]
            .as_array()
            .unwrap()
            .contains(&Value::String(n.ids[1].to_string()))
    );
    // Remote return routes converge from the signed withdrawal; local policy
    // acknowledgement does not claim that every other node has already heard it.
    n.wait(Duration::from_secs(15), |n| {
        n.call(
            0,
            Request::Trace {
                target: n.ids[3].to_string(),
            },
        )
        .is_some_and(|t| t["complete"] == true && t["hops"][0]["node"] == n.ids[2].to_string())
    });
    let trace = n
        .call(
            0,
            Request::Trace {
                target: n.ids[3].to_string(),
            },
        )
        .unwrap();
    assert_eq!(trace["complete"], true, "{trace}");
    assert_eq!(trace["hops"][0]["node"], n.ids[2].to_string());
    assert_eq!(ping(&n)["hop_encrypted"], true);
    membership(&n, true, 3);
    assert!(ping(&n)["error"].is_string());
    // D still endorses B; repeated gossip cannot override A's explicit denial.
    thread::sleep(Duration::from_secs(6));
    assert!(ping(&n)["error"].is_string());
    assert_eq!(n.call(0, Request::Status).unwrap()["boot_id"], boot);
    membership(&n, false, 3);
    assert_eq!(ping(&n)["hop_encrypted"], true);
    membership(&n, true, 3);
    membership(&n, true, 2);
    assert_eq!(n.call(0, Request::Status).unwrap()["nodes"], 1);
    let config = Config::load(&n.paths[0]).unwrap();
    assert_eq!(config.denied.len(), 3);
    assert_eq!(
        config.peers.len(),
        2,
        "denial must not silently delete configured peers"
    );
    n.children[0].kill().unwrap();
    n.children[0].wait().unwrap();
    n.children[0] = Command::new(env!("CARGO_BIN_EXE_nnlan"))
        .args(["--config", n.paths[0].to_str().unwrap(), "run"])
        .stdout(Stdio::null())
        .stderr(
            fs::OpenOptions::new()
                .append(true)
                .open(&n.logs[0])
                .unwrap(),
        )
        .spawn()
        .unwrap();
    n.wait(Duration::from_secs(12), |n| {
        n.call(0, Request::Status)
            .is_some_and(|s| s["boot_id"] != boot && s["nodes"] == 1)
    });
    assert_eq!(
        n.call(0, Request::Members).unwrap()["denied"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    membership(&n, false, 2);
    n.wait(Duration::from_secs(18), |n| {
        n.call(0, Request::Status).is_some_and(|s| s["nodes"] == 2)
    });
    assert!(ping(&n)["error"].is_string());
    membership(&n, false, 3);
    n.wait(Duration::from_secs(12), |n| {
        ping(n)["hop_encrypted"] == true
    });
    let output = Command::new(env!("CARGO_BIN_EXE_nnlan"))
        .args([
            "--config",
            n.paths[0].to_str().unwrap(),
            "members",
            "deny",
            &n.ids[3].to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(ping(&n)["error"].is_string());
}

#[test]
fn failed_membership_persistence_never_reports_success_or_changes_live_policy() {
    use nnlan::runtime::admin::MemberAction;
    let n = Network::start(&["a"], &[vec![]], &[1]);
    let other = Identity::generate().unwrap().node_id();
    let backup = n.paths[0].with_extension("backup");
    fs::rename(&n.paths[0], &backup).unwrap();
    fs::create_dir(&n.paths[0]).unwrap();
    let result = n
        .call(
            0,
            Request::Member {
                action: MemberAction::Deny { node: other },
            },
        )
        .unwrap();
    assert!(result["error"].is_string(), "{result}");
    assert!(
        n.call(0, Request::Members).unwrap()["denied"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fs::remove_dir(&n.paths[0]).unwrap();
    fs::rename(backup, &n.paths[0]).unwrap();
    assert!(Config::load(&n.paths[0]).unwrap().denied.is_empty());
}

#[test]
fn real_ipv4_collision_is_resolved_persisted_and_survives_process_restart() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/ipv4-collision.json")).unwrap();
    let identities: Vec<_> = ["seed_a", "seed_b"]
        .iter()
        .map(|name| {
            let seed = fixture[*name].as_str().unwrap();
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(b"GGBKEY1\n").unwrap();
            for index in (0..64).step_by(2) {
                file.write_all(&[u8::from_str_radix(&seed[index..index + 2], 16).unwrap()])
                    .unwrap();
            }
            Identity::load(file.path()).unwrap()
        })
        .collect();
    assert_eq!(
        nnlan::address::candidate(identities[0].node_id(), 0).ipv4,
        nnlan::address::candidate(identities[1].node_id(), 0).ipv4
    );
    let mut network =
        Network::start_with_identities(&["a", "b"], &[vec![1], vec![]], &[1, 1], identities);
    let before: Vec<_> = (0..2)
        .map(|i| network.call(i, Request::Status).unwrap())
        .collect();
    assert_ne!(before[0]["address"]["ipv4"], before[1]["address"]["ipv4"]);
    let loser = if network.ids[0] > network.ids[1] {
        0
    } else {
        1
    };
    assert!(before[loser]["address"]["probe"].as_u64().unwrap() > 0);
    assert_eq!(before[1 - loser]["address"]["probe"], 0);
    let before_ping = network
        .call(
            1 - loser,
            Request::Ping {
                target: network.ids[loser].to_string(),
                size: 128,
            },
        )
        .unwrap();
    assert_eq!(before_ping["hop_encrypted"], true, "{before_ping}");
    // SIGKILL, not a cooperative restart: reservation and probe were fsynced before use.
    network.children[loser].kill().unwrap();
    network.children[loser].wait().unwrap();
    network.children[loser] = Command::new(env!("CARGO_BIN_EXE_nnlan"))
        .args(["--config", network.paths[loser].to_str().unwrap(), "run"])
        .stdout(Stdio::null())
        .stderr(
            fs::OpenOptions::new()
                .append(true)
                .open(&network.logs[loser])
                .unwrap(),
        )
        .spawn()
        .unwrap();
    network.wait(Duration::from_secs(18), |n| {
        let Some(new) = n.call(loser, Request::Status) else {
            return false;
        };
        let Some(peers) = n.call(1 - loser, Request::Peers) else {
            return false;
        };
        new["nodes"] == 2
            && peers.as_array().unwrap().iter().any(|p| {
                p["record"]["descriptor"]["node"] == n.ids[loser].to_string()
                    && p["record"]["descriptor"]["boot_id"] == new["boot_id"]
            })
    });
    let after = network.call(loser, Request::Status).unwrap();
    assert_eq!(after["address"], before[loser]["address"]);
    assert_ne!(after["boot_id"], before[loser]["boot_id"]);
    let ping = network
        .call(
            1 - loser,
            Request::Ping {
                target: network.ids[loser].to_string(),
                size: 128,
            },
        )
        .unwrap();
    assert_eq!(ping["hop_encrypted"], true, "{ping}");
}

#[test]
fn no_tun_never_claims_or_persists_kernel_route_changes() {
    use nnlan::runtime::admin::{ExitAction, RouteAction};
    let network = Network::start(&["a"], &[vec![]], &[1]);
    let before = fs::read(&network.paths[0]).unwrap();
    let result = network
        .call(
            0,
            Request::Route {
                action: RouteAction::Advertise {
                    prefix: "192.168.77.0/24".parse().unwrap(),
                },
            },
        )
        .unwrap();
    assert!(result["error"].as_str().unwrap().contains("TUN"));
    assert_eq!(fs::read(&network.paths[0]).unwrap(), before);
    let routes = network.call(0, Request::Routes).unwrap();
    assert_eq!(routes["kernel_subnet_policy_installed"], false);
    assert_eq!(routes["accepted"].as_array().unwrap().len(), 0);
    for action in [
        ExitAction::Serve { enabled: true },
        ExitAction::Off,
        ExitAction::Use {
            target: "unknown-node".into(),
        },
    ] {
        let result = network.call(0, Request::Exit { action }).unwrap();
        assert!(result["error"].as_str().unwrap().contains("TUN"));
        assert_eq!(fs::read(&network.paths[0]).unwrap(), before);
    }
    let status = network.call(0, Request::Status).unwrap();
    assert_eq!(status["kernel_exit_guard_installed"], false);
    assert_eq!(status["dns_forwarder_running"], false);
}

#[path = "daemon/admission.rs"]
mod admission;
