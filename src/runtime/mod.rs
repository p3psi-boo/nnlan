//! Single-owner overlay event loop; workers handle admin, DNS and interface snapshots.
pub mod admin;
mod candidates;
mod control;
mod data;
mod diagnostics;
mod dns;
mod gossip;
mod ingress;
mod interfaces;
mod kernel;
mod membership;
mod pacer_wake;
mod resolver;
mod routes;
mod state;
mod tunnel;

use crate::{
    address::candidate,
    config::Config,
    identity::{Identity, NodeId},
    plan::Plan,
    transport::{
        link::Message,
        udp::{Event, UdpTransport},
        wire::{self, Envelope},
    },
};
use anyhow::{Context, Result, ensure};
use control::{Control, Descriptor, Record, unix_time};
use diagnostics::Diagnostics;
use serde_json::{Value, json};
use state::State;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tunnel::Tunnel;

const RECORD_MESSAGE: u8 = 1;
// Four refresh opportunities per signed-record lifetime; actual changes publish immediately.
const RECORD_REFRESH: Duration = Duration::from_secs(control::RECORD_TTL / 4);
const ENVELOPE_MESSAGE: u8 = 2;
const DIRECT_DATA_MESSAGE: u8 = 3;
const IDLE_AFTER: Duration = Duration::from_secs(60);
const CANDIDATE_STAGGER: Duration = Duration::from_millis(500);
const DIRECT_DEMAND: Duration = Duration::from_secs(8);

struct DirectAttempt {
    last: Instant,
    index: usize,
    demand: Option<Instant>,
}

pub struct Engine {
    config: Config,
    config_path: PathBuf,
    kernel: Option<kernel::Policy>,
    kernel_address: Option<std::net::Ipv4Addr>,
    identity: Identity,
    boot_id: u64,
    state: State,
    control: Control,
    transport: UdpTransport,
    tunnel: Option<Tunnel>,
    ingress: ingress::Ingress,
    dns: Option<dns::Forwarder>,
    diagnostics: Diagnostics,
    kernel_waiters: Vec<(oneshot::Sender<Value>, Value)>,
    gossip: BTreeMap<NodeId, gossip::Gossip>,
    endpoints: candidates::Candidates,
    configured: BTreeMap<NodeId, Vec<SocketAddr>>,
    direct_attempt: BTreeMap<NodeId, DirectAttempt>,
    verify_limits: BTreeMap<NodeId, (Instant, u32)>,
    publish_at: Instant,
    maintain_at: Instant,
    connect_at: Instant,
    retire_at: Instant,
    dropped: u64,
    forwarded: u64,
    ip_received: u64,
    ip_sent: u64,
    stopping: bool,
}

/// Early boot entry point. No address, resolver, TUN or sequence state required.
/// Do not clean up on exit: the guard must outlive all userspace failures.
pub fn guard(config_path: &Path) -> Result<Value> {
    let config = Config::load(config_path)?;
    ensure!(
        config.tun.enabled,
        "kernel guard requires TUN enabled in configuration"
    );
    let identity = Identity::load(&config.identity_path(config_path))?;
    let _lock = State::lock(&config, config_path)?;
    let mut policy = kernel::Policy::open(
        identity.node_id(),
        &config.tun.name,
        config.listen.port(),
        config.dhcp_client_uid,
        true,
    )?;
    policy.protect(&config.routes)?;
    Ok(json!({
        "node_id": identity.node_id(),
        "kernel_subnet_policy_installed": true,
        "kernel_exit_guard_installed": config.routes.exit_node.is_some(),
        "network_running": false,
    }))
}

pub async fn run(config_path: &Path, no_tun: bool) -> Result<()> {
    let mut config = Config::load(config_path)?;
    if no_tun {
        config.tun.enabled = false;
    }
    let identity = Identity::load(&config.identity_path(config_path))?;
    Plan::build(&config, &identity)?;
    ensure!(
        config.tun.enabled
            || (config.routes.advertise.is_empty()
                && config.routes.accept.is_empty()
                && config.routes.exit_node.is_none()
                && !config.routes.serve_exit),
        "subnet/exit routing requires TUN"
    );
    let state = State::open(&config, config_path, identity.node_id())?;
    let address = candidate(identity.node_id(), state.probe());
    let mut kernel = if config.tun.enabled {
        let mut policy = kernel::Policy::open(
            identity.node_id(),
            &config.tun.name,
            config.listen.port(),
            config.dhcp_client_uid,
            true,
        )?;
        policy.protect(&config.routes)?;
        Some(policy)
    } else {
        None
    };
    kernel::Policy::preflight(&config.routes)?;
    let tunnel = if config.tun.enabled {
        Some(Tunnel::create(&config.tun, address)?)
    } else {
        None
    };
    if let Some(policy) = &mut kernel {
        policy.apply(&config.routes, address)?;
    }
    let dns = if config.routes.serve_exit {
        Some(dns::Forwarder::start(
            resolver::servers(&config, false)?,
            &config.tun.name,
        )?)
    } else {
        None
    };
    let mut transport = UdpTransport::bind(
        &identity,
        config.listen,
        config.max_neighbors,
        config.peers.iter().map(|p| p.public_key),
        u64::from(config.bandwidth_mbps) * 1_000_000,
        config.tun.enabled.then_some(kernel::MARK),
        config.repair,
    )?;
    transport.set_denied(config.denied.clone());
    let peer_resolver = resolver::build(&config)?;
    let mut control = Control::new(identity.node_id());
    control.set_denied(config.denied.clone());
    let now = Instant::now();
    // Interface discovery is optional bootstrap information, not admission.
    // The monitor below subscribes then immediately snapshots/retries. Do not
    // duplicate that query here or make its timeout abort a configured peer.
    let endpoints = candidates::Candidates::new(&config, BTreeSet::new(), now);
    let mut engine = Engine {
        config: config.clone(),
        config_path: config_path.to_owned(),
        kernel,
        kernel_address: Some(address.ipv4),
        identity,
        boot_id: wire::random_id()?,
        state,
        control,
        transport,
        tunnel,
        ingress: ingress::Ingress::new(config.tun.mtu),
        dns,
        diagnostics: Diagnostics::default(),
        kernel_waiters: Vec::new(),
        gossip: BTreeMap::new(),
        endpoints,
        configured: BTreeMap::new(),
        direct_attempt: BTreeMap::new(),
        verify_limits: BTreeMap::new(),
        publish_at: now,
        maintain_at: now,
        connect_at: now,
        retire_at: now,
        dropped: 0,
        forwarded: 0,
        ip_received: 0,
        ip_sent: 0,
        stopping: false,
    };
    engine.publish(now)?;
    engine.refresh(unix_time()?)?;
    let (_server, mut admin) = admin::Server::start(admin::socket_path(config_path))?;
    let (resolved_tx, mut resolved_rx) = mpsc::channel(128);
    let (interfaces_tx, mut interfaces_rx) = mpsc::channel(1);
    let interfaces = tokio::spawn(interfaces::monitor(config.listen, interfaces_tx));
    let resolver = tokio::spawn(resolver::run(config, peer_resolver, resolved_tx));
    eprintln!(
        "nnlan ready: {} {} {}",
        engine.identity.node_id(),
        address.ipv4,
        address.ipv6
    );
    let result = engine
        .event_loop(&mut admin, &mut resolved_rx, &mut interfaces_rx)
        .await;
    resolver.abort();
    interfaces.abort();
    result
}

impl Engine {
    async fn event_loop(
        &mut self,
        admin: &mut mpsc::Receiver<admin::Call>,
        resolved: &mut mpsc::Receiver<(NodeId, Vec<SocketAddr>)>,
        interfaces: &mut mpsc::Receiver<BTreeSet<SocketAddr>>,
    ) -> Result<()> {
        let mut udp_buffer = [0; wire::MAX_UDP + 1];
        let mut tun_reader = self
            .tunnel
            .as_ref()
            .map(|_| tunnel::Reader::new(self.config.tun.mtu));
        let mut tick = tokio::time::interval(Duration::from_millis(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let interrupt = tokio::signal::ctrl_c();
        tokio::pin!(interrupt);
        let mut flushed_at = Instant::now();
        let mut send_wake = pacer_wake::PacerWake::new()?;
        let mut ingress_ready = false;
        while !self.stopping {
            tokio::select! {
                _ = std::future::ready(()), if ingress_ready => {},
                _ = &mut interrupt => break,
                _ = terminate.recv() => break,
                Some((node, addresses)) = resolved.recv() => { self.configured.insert(node, addresses); self.connect_at = Instant::now() - Duration::from_secs(1); },
                Some(addresses) = interfaces.recv() => {
                    let now = Instant::now();
                    if self.endpoints.update_local(addresses, now) { self.publish(now)?; }
                },
                Some(call) = admin.recv() => self.admin(call, Instant::now()).await,
                result = self.transport.recv(&mut udp_buffer) => {
                    let started = Instant::now();
                    let mut packet = result;
                    for index in 0..32 {
                        let (n, from, local) = match packet {
                            Ok(packet) => packet,
                            Err(error) if crate::transport::udp::is_path_error(&error) => {
                                if error.kind() != std::io::ErrorKind::WouldBlock { self.transport.socket_dropped += 1; }
                                break;
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let now = Instant::now();
                        let events = self.transport.receive(&udp_buffer[..n], from, local, now).await;
                        for event in events {
                            let untrusted_message = matches!(&event, Event::Message(_, _));
                            if let Err(error) = self.event(event, now).await {
                                if !untrusted_message { return Err(error); }
                                self.dropped += 1;
                                if self.dropped <= 8 || self.dropped.is_power_of_two() {
                                    eprintln!("overlay event dropped ({}): {error:#}", self.dropped);
                                }
                            }
                        }
                        if index == 31 || started.elapsed() >= Duration::from_micros(100) { break; }
                        packet = self.transport.try_recv(&mut udp_buffer);
                    }
                }
                result = async { match &self.tunnel { Some(t) => tun_reader.as_mut().expect("TUN reader").ready(&t.device).await, None => std::future::pending().await } } => {
                    result?;
                    let started = Instant::now();
                    let dropped = self.ingress.stats.dropped();
                    // Drain ready kernel aggregates cheaply, without route lookup,
                    // encryption or waiting for one destination's link capacity.
                    for _ in 0..4096 {
                        let reader = tun_reader.as_mut().expect("TUN reader");
                        match reader.try_ready(&self.tunnel.as_ref().expect("TUN").device) {
                            Ok(()) => (),
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error.into()),
                        }
                        let Some(packet) = reader.next() else { break; };
                        self.ingress.enqueue(packet, Instant::now());
                        if started.elapsed() >= Duration::from_micros(500) { break; }
                    }
                    self.dropped += self.ingress.stats.dropped() - dropped;
                }
                _ = tick.tick() => {
                    flushed_at = Instant::now();
                    self.tick(flushed_at).await?;
                },
                result = send_wake.wait() => {
                    result?;
                    flushed_at = Instant::now();
                    self.transport.flush(flushed_at).await?;
                },
            }
            ingress_ready = self.drain_ingress().await;
            // Drain the bounded receive batch before processing another event.
            // No timer or low-rate coalescing delay is added.
            if let Some(tunnel) = &mut self.tunnel {
                tunnel.flush().await?;
            }
            // At high PPS a millisecond timer needlessly holds ready packets.
            // Pump on I/O progress, at most every 250 us; no busy loop when idle,
            // no extra tokens/burst, and bounded fair work before returning to select.
            let now = Instant::now();
            if now.saturating_duration_since(flushed_at) >= Duration::from_micros(250) {
                self.transport.flush(now).await?;
                flushed_at = now;
            }
            // With TUN/GRO batching there may be no I/O event to drive the next
            // sub-ms burst. Arm one high-resolution wake only for queued data;
            // slow paths stay on the existing 1 ms maintenance timer.
            let now = Instant::now();
            let wake = self
                .transport
                .send_delay(now)
                .map(|delay| (now + delay).max(flushed_at + Duration::from_micros(250)))
                .filter(|at| at.saturating_duration_since(now) < Duration::from_millis(1));
            send_wake.arm(wake)?;
        }
        // Let owner-only admin clients flush the shutdown response.
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok(())
    }
    fn publish(&mut self, now: Instant) -> Result<()> {
        self.endpoints.expire(now);
        let mut subnets = self.config.routes.advertise.clone();
        subnets.sort();
        let neighbors: Vec<_> = self.transport.connected().collect();
        let pinned = neighbors
            .iter()
            .enumerate()
            .filter_map(|(index, node)| {
                self.config
                    .peers
                    .iter()
                    .any(|p| p.public_key == *node)
                    .then_some(index as u8)
            })
            .collect();
        let descriptor = Descriptor {
            node: self.identity.node_id(),
            boot_id: self.boot_id,
            name: self.config.name.clone(),
            probe: self.state.probe(),
            relay: self.config.relay,
            endpoints: self.endpoints.advertised().iter().copied().collect(),
            neighbors,
            pinned,
            subnets,
            serve_exit: self.config.routes.serve_exit,
        };
        let record = Record::issue(
            &self.identity,
            descriptor,
            self.state.sequence()?,
            unix_time()?,
        )?;
        self.control.insert_verified(record)?;
        self.control.direct(self.transport.connected());
        for queue in self.gossip.values_mut() {
            queue.insert(self.identity.node_id());
        }
        self.publish_at = now;
        Ok(())
    }
    fn refresh(&mut self, now: u64) -> Result<()> {
        if !self.control.refresh(now)? {
            return Ok(());
        }
        let revoked = self.control.take_revoked();
        if !revoked.is_empty() {
            // Serialized link queues no longer retain overlay identity labels.
            // Purge bounded send/FEC/RTX state rather than send revoked traffic;
            // keep live links, keys and monotonic frame counters intact.
            self.transport.discard_queued();
            for node in revoked {
                self.forget_member(node);
            }
        }
        let local = self.identity.node_id();
        let mut probe = self.state.probe();
        for _ in 0..4096 {
            let address = candidate(local, probe);
            if self
                .control
                .ipv4_owner(address.ipv4)
                .is_none_or(|owner| local <= owner)
            {
                break;
            }
            probe = probe.checked_add(1).context("IPv4 probe exhausted")?;
        }
        ensure!(
            self.control
                .ipv4_owner(candidate(local, probe).ipv4)
                .is_none_or(|owner| local <= owner),
            "IPv4 collision retry budget"
        );
        if probe != self.state.probe() {
            self.state.set_probe(probe)?;
            self.publish(Instant::now())?;
            self.control.refresh(now)?;
        }
        if let Some(tunnel) = &mut self.tunnel {
            tunnel.address(candidate(local, self.state.probe()))?;
            let mut routes = BTreeSet::new();
            for record in self.control.records() {
                let node = record.descriptor.node;
                if node == local || !self.control.trusted(node) {
                    continue;
                }
                let a = self
                    .control
                    .addresses(node)
                    .context("record address index")?;
                if self.control.ipv4_owner(a.ipv4) == Some(node) {
                    routes.insert(IpAddr::V4(a.ipv4));
                }
                routes.insert(IpAddr::V6(a.ipv6));
            }
            tunnel.sync_routes(routes)?;
            if probe != 0 && self.kernel_address != Some(candidate(local, probe).ipv4) {
                if let Some(policy) = &mut self.kernel {
                    policy.apply(&self.config.routes, candidate(local, probe))?;
                }
                self.kernel_address = Some(candidate(local, probe).ipv4);
            }
        }
        Ok(())
    }
    async fn event(&mut self, event: Event, now: Instant) -> Result<()> {
        match event {
            Event::Connected(peer) => {
                self.direct_attempt.remove(&peer);
                self.gossip.insert(
                    peer,
                    gossip::Gossip::new(
                        self.identity.node_id(),
                        self.control.records().map(|r| r.descriptor.node),
                        now,
                    ),
                );
                self.publish(now)?;
                self.refresh(unix_time()?)?;
            }
            Event::Disconnected(peer) => {
                self.endpoints.disconnected(peer);
                self.gossip.remove(&peer);
                self.verify_limits.remove(&peer);
                self.direct_attempt.remove(&peer);
                self.publish(now)?;
                self.refresh(unix_time()?)?;
            }
            Event::ObservedEndpoint { observer, address } => {
                if self.endpoints.observe(observer, address, now) {
                    self.publish(now)?;
                }
            }
            Event::EndpointChanged(_, _) => (),
            Event::Message(peer, message) => match message.kind {
                RECORD_MESSAGE => {
                    self.admit_signature(peer, now)?;
                    let record = Record::decode(&message.payload, unix_time()?)?;
                    let node = record.descriptor.node;
                    if node != self.identity.node_id() && self.control.insert_verified(record)? {
                        for (&other, queue) in &mut self.gossip {
                            if other != peer {
                                queue.insert(node);
                            }
                        }
                    }
                }
                ENVELOPE_MESSAGE | DIRECT_DATA_MESSAGE => {
                    ensure!(self.control.trusted(peer), "untrusted forwarding neighbor");
                    let envelope = if message.kind == DIRECT_DATA_MESSAGE {
                        Envelope::from_direct(peer, self.identity.node_id(), message.payload)?
                    } else {
                        Envelope::decode_with(&message.payload, |bytes| {
                            self.control.known_identity(bytes)
                        })?
                    };
                    if matches!(envelope.kind, wire::TRACE | wire::TRACE_REPLY) {
                        self.admit_signature(peer, now)?;
                    }
                    self.envelope(envelope, now).await?;
                    self.transport.used(peer, now);
                }
                _ => anyhow::bail!("unknown overlay message"),
            },
        }
        Ok(())
    }
    fn admit_signature(&mut self, peer: NodeId, now: Instant) -> Result<()> {
        let limit = self.verify_limits.entry(peer).or_insert((now, 0));
        if now.saturating_duration_since(limit.0) >= Duration::from_secs(1) {
            *limit = (now, 0);
        }
        ensure!(limit.1 < 256, "control signature verification rate");
        limit.1 += 1;
        Ok(())
    }
    async fn tick(&mut self, now: Instant) -> Result<()> {
        let routes_ready = self
            .tunnel
            .as_ref()
            .map_or(Ok(true), Tunnel::routes_ready)?;
        self.kernel_waiters.retain(|(reply, _)| !reply.is_closed());
        if routes_ready {
            for (reply, value) in self.kernel_waiters.drain(..) {
                let _ = reply.send(value);
            }
        }
        ensure!(
            self.dns.as_ref().is_none_or(dns::Forwarder::running),
            "Exit DNS service stopped"
        );
        let events = self.transport.tick(now).await?;
        for event in events {
            self.event(event, now).await?;
        }
        if now.saturating_duration_since(self.connect_at) >= Duration::from_secs(1) {
            let configured: Vec<_> = self
                .configured
                .iter()
                .filter(|(node, _)| !self.transport.has_peer(**node))
                .map(|(&node, addresses)| (node, addresses.clone()))
                .collect();
            for (node, addresses) in configured {
                self.try_candidates(node, &addresses, now).await;
            }
            // A single user packet is enough to drive a bounded attempt window.
            // Merely discovering a peer does not create demand, and timer-driven
            // attempts never extend it. Configured peers retain their own retry.
            let demanded: Vec<_> = self
                .direct_attempt
                .iter()
                .filter(|(peer, attempt)| {
                    !self.configured.contains_key(*peer)
                        && attempt
                            .demand
                            .is_some_and(|at| now.saturating_duration_since(at) < DIRECT_DEMAND)
                })
                .map(|(&peer, _)| peer)
                .collect();
            for peer in demanded {
                if self.control.trusted(peer)
                    && let Some(record) = self.control.record(peer)
                {
                    let addresses = record.descriptor.endpoints.clone();
                    self.try_candidates(peer, &addresses, now).await;
                }
            }
            self.connect_at = now;
        }
        if now.saturating_duration_since(self.publish_at) >= RECORD_REFRESH {
            self.publish(now)?;
        }
        if now.saturating_duration_since(self.maintain_at) >= Duration::from_millis(100) {
            // Dynamic candidate withdrawal must not wait for a periodic record renewal.
            if self.endpoints.expire(now) {
                self.publish(now)?;
            }
            self.refresh(unix_time()?)?;
            self.diagnostics.maintain(now);
            self.maintain_at = now;
        }
        if now.saturating_duration_since(self.retire_at) >= Duration::from_secs(1) {
            self.refresh(unix_time()?)?;
            // One owner per edge and one removal per tick. Backups come from
            // the retained graph, not other shortcuts that may also disappear.
            let local = self.identity.node_id();
            for peer in self.transport.idle_candidates(now, IDLE_AFTER) {
                if local < peer && self.control.retirement_path(peer).is_some() {
                    if let Some(event) = self.transport.retire_idle(peer, IDLE_AFTER, now).await? {
                        self.event(event, now).await?;
                    }
                    break;
                }
            }
            self.retire_at = now;
        }
        let peers: Vec<_> = self.gossip.keys().copied().collect();
        for peer in peers {
            let Some(node) = self.gossip.get_mut(&peer).and_then(|queue| queue.pop(now)) else {
                continue;
            };
            let Some(record) = self.control.record(node) else {
                continue;
            };
            if self
                .transport
                .send(
                    peer,
                    Message {
                        kind: RECORD_MESSAGE,
                        payload: serde_json::to_vec(record)?,
                    },
                    now,
                )
                .is_err()
            {
                // Retry the latest version fairly, without spinning on a full
                // link queue or blocking updates for all other identities.
                self.gossip
                    .get_mut(&peer)
                    .expect("gossip peer")
                    .insert(node);
            }
        }
        Ok(())
    }
    async fn try_candidates(&mut self, peer: NodeId, endpoints: &[SocketAddr], now: Instant) {
        if self.config.denied.contains(&peer) || self.transport.has_peer(peer) {
            return;
        }
        // Different NATs often reuse the same private IP:port. Dialing our own
        // known endpoint can only hit this listener, not the pinned remote key;
        // don't spend an entire handshake retry window on that candidate.
        let mut endpoints = endpoints
            .iter()
            .copied()
            .filter(|endpoint| !self.endpoints.is_local_endpoint(endpoint));
        let count = endpoints.clone().count();
        if count == 0 {
            return;
        }
        if let Some(attempt) = self.direct_attempt.get(&peer)
            && now.saturating_duration_since(attempt.last) < CANDIDATE_STAGGER
        {
            return;
        }
        if self.direct_attempt.len() >= control::MAX_NODES
            && !self.direct_attempt.contains_key(&peer)
        {
            return;
        }
        let index = self
            .direct_attempt
            .get(&peer)
            .map_or(0, |attempt| attempt.index.wrapping_add(1));
        let endpoint = endpoints.nth(index % count).expect("nonempty candidates");
        let demand = self
            .direct_attempt
            .get(&peer)
            .and_then(|attempt| attempt.demand);
        self.direct_attempt.insert(
            peer,
            DirectAttempt {
                last: now,
                index,
                demand,
            },
        );
        let _ = self.transport.connect_candidate(peer, endpoint, now).await;
    }
    async fn try_direct(&mut self, peer: NodeId, now: Instant) {
        if !self.control.trusted(peer) || self.transport.has_peer(peer) {
            return;
        }
        if let Some(record) = self.control.record(peer) {
            let endpoints = record.descriptor.endpoints.clone();
            self.try_candidates(peer, &endpoints, now).await;
            if let Some(attempt) = self.direct_attempt.get_mut(&peer) {
                attempt.demand = Some(now);
            }
        }
    }
    fn status(&self) -> Value {
        let node = self.identity.node_id();
        json!({"node":node,"boot_id":self.boot_id,"name":self.config.name,"address":candidate(node,self.state.probe()),"network_running":true,"wire_protocol":"GGB3","encryption":"hop-by-hop","addresses_claimed":self.control.ipv4_owner(candidate(node,self.state.probe()).ipv4)==Some(node),"tun_enabled":self.tunnel.is_some(),"kernel_routes_ready":self.tunnel.as_ref().is_none_or(|t|t.routes_ready().unwrap_or(false)),"nodes":self.control.records().filter(|r|self.control.trusted(r.descriptor.node)).count(),"neighbors":self.transport.status(Instant::now()),"relay":self.config.relay,"repair":self.config.repair,"forwarded":self.forwarded,"dropped":self.dropped,"tun_backpressure":self.ingress.stats,"ip_sent":self.ip_sent,"ip_received":self.ip_received,"invalid_udp":self.transport.invalid_packets,"udp_socket_dropped":self.transport.socket_dropped,"idle_retired":self.transport.idle_retired,"kernel_exit_guard_installed":self.kernel.is_some() && self.config.routes.exit_node.is_some(),"dns_forwarder_running":self.dns.as_ref().is_some_and(dns::Forwarder::running),"exit_node":self.config.routes.exit_node,"kernel_subnet_policy_installed":self.kernel.is_some()})
    }
    async fn admin(&mut self, call: admin::Call, now: Instant) {
        let admin::Call { request, reply } = call;
        let membership_change = matches!(&request, admin::Request::Member { .. });
        if membership_change && self.kernel_waiters.len() >= 16 {
            let _ = reply.send(json!({"error":"pending membership update capacity"}));
            return;
        }
        let result=match request {
            admin::Request::Status=>Ok(self.status()),
            admin::Request::Members=>Ok(self.members_status()),
            admin::Request::Member { action } => self.update_member(action, now),
            admin::Request::Peers=>Ok(json!(self.control.records().map(|r|json!({"record":r,"trusted":self.control.trusted(r.descriptor.node),"direct":self.transport.has_peer(r.descriptor.node),"address":candidate(r.descriptor.node,r.descriptor.probe),"path":self.control.predicted_path(r.descriptor.node)})).collect::<Vec<_>>())),
            admin::Request::Routes=>Ok(self.routes_status()),
            admin::Request::Route { action } => self.update_route(action, now),
            admin::Request::Exit { action } => self.update_exit(action, now),
            admin::Request::Shutdown=>{self.stopping=true;Ok(json!({"stopping":true}))},
            admin::Request::Trace{target}=>{self.start_trace(&target,reply,now);return;},
            admin::Request::Ping{target,size}=>{self.start_ping(&target,size,reply,now).await;return;},
        };
        let success = result.is_ok();
        let value = result.unwrap_or_else(|e: anyhow::Error| json!({"error":e.to_string()}));
        if membership_change && success && self.tunnel.is_some() {
            // Membership is already enforced in the data path. Acknowledge the
            // management operation only after kernel route removal/addition;
            // waiting must not block UDP, TUN or subsequent revocations.
            self.kernel_waiters.push((reply, value));
        } else {
            let _ = reply.send(value);
        }
    }
}

/// Explicit recovery after daemon failure; never contacts or edits another netns.
pub fn exit_offline(config_path: &Path) -> Result<Value> {
    routes::exit_off(config_path)
}
