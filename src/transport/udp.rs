//! Real UDP adjacency: Noise authentication, bounded admission, keepalives, rekey,
//! address observation and authenticated return-routability before endpoint migration.
use super::{
    crypto::Crypto,
    link::{CacheBudget, Controller, Link, LinkStats, Message},
    wire::{self, DATA, HS1, LINK_SCOPE, MAX_UDP, Packet},
};
use crate::{
    config::RepairConfig,
    identity::{Identity, NodeId},
    peers::NeighborSet,
    reliability::fec::FecScope,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

mod pmtu;
mod socket;
use socket::Source;

const KEEPALIVE: Duration = Duration::from_secs(1);
const DEAD_AFTER: Duration = Duration::from_secs(6);
const REKEY_AFTER: Duration = Duration::from_secs(120);
const INTERNAL: u8 = 0;
// Bundle: direct DATA identities, compact single sources, lossless batch ACKs.
// v1 was an archived local pilot without compact ACKs; never infer v2 from it.
const COMPACT_VERSION: u8 = 2;
const RETIRE: u8 = 253;

/// Errors attributable to an underlay path, not a broken daemon socket.
/// An unconnected UDP receive error has no trustworthy peer association.
pub fn is_path_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
        || matches!(
            error.kind(),
            std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::WouldBlock
        )
}

fn canonical_address(address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = address
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(v4.into(), address.port());
    }
    address
}

pub enum Event {
    Connected(NodeId),
    Disconnected(NodeId),
    Message(NodeId, Message),
    ObservedEndpoint {
        observer: NodeId,
        address: SocketAddr,
    },
    EndpointChanged(NodeId, SocketAddr),
}

struct Peer {
    endpoint: SocketAddr,
    local: Option<Source>,
    seen: Instant,
    heartbeat: Instant,
    used: Instant,
    pmtu: pmtu::PathMtu,
    control: Controller,
    // Reused per-tick aggregate; no allocation or per-key budget.
    load: (usize, bool),
}
struct Flight {
    peer: NodeId,
    local: Option<Source>,
    endpoint: SocketAddr,
    created: Instant,
}
struct Challenge {
    endpoint: SocketAddr,
    local: Option<Source>,
    token: u64,
    expires: Instant,
}

#[derive(Serialize)]
pub struct PeerStatus {
    pub node: NodeId,
    pub endpoint: SocketAddr,
    /// Public wire session identifier, never key material.
    pub key_epoch: Option<u64>,
    pub idle_ms: u128,
    pub traffic_idle_ms: u128,
    pub link: LinkStats,
    pub pmtu: pmtu::Status,
}

pub struct UdpTransport {
    socket: UdpSocket,
    receiver: socket::Receiver,
    gso: bool,
    crypto: Crypto,
    neighbors: NeighborSet,
    denied: BTreeSet<NodeId>,
    peers: BTreeMap<NodeId, Peer>,
    flights: BTreeMap<u64, Flight>,
    links: BTreeMap<u64, Link>,
    cache_budget: CacheBudget,
    challenges: BTreeMap<NodeId, Challenge>,
    max_bps: u64,
    repair: RepairConfig,
    tokens: f64,
    updated: Instant,
    cursor: usize,
    pub invalid_packets: u64,
    pub socket_dropped: u64,
    pub idle_retired: u64,
}

impl UdpTransport {
    pub fn bind(
        identity: &Identity,
        listen: SocketAddr,
        limit: usize,
        configured: impl IntoIterator<Item = NodeId>,
        max_bps: u64,
        mark: Option<u32>,
        repair: RepairConfig,
    ) -> Result<Self> {
        ensure!(max_bps >= 64_000, "invalid transport bandwidth");
        let socket = Socket::new(
            Domain::for_address(listen),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if listen.is_ipv6() {
            socket.set_only_v6(false)?;
        }
        // DF / no source fragmentation, including IPv4-mapped destinations on
        // the dual-stack socket. PROBE ignores stale/untrusted ICMP route-cache
        // ceilings; encrypted packetization-layer probes establish the limit.
        rustix::net::sockopt::set_ip_mtu_discover(
            &socket,
            rustix::net::sockopt::Ipv4PathMtuDiscovery::PROBE,
        )?;
        if listen.is_ipv6() {
            rustix::net::sockopt::set_ipv6_mtu_discover(
                &socket,
                rustix::net::sockopt::Ipv6PathMtuDiscovery::PROBE,
            )?;
        }
        socket::enable(&socket, listen.is_ipv6())?;
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(4 * 1024 * 1024)?;
        socket.set_send_buffer_size(4 * 1024 * 1024)?;
        if let Some(mark) = mark {
            socket.set_mark(mark).context("set underlay routing mark")?;
        }
        socket.bind(&listen.into())?;
        let socket = UdpSocket::from_std(socket.into())?;
        Ok(Self {
            socket,
            receiver: socket::Receiver::new(),
            gso: true,
            crypto: Crypto::new(identity)?,
            neighbors: NeighborSet::new(limit, configured)?,
            denied: BTreeSet::new(),
            peers: BTreeMap::new(),
            flights: BTreeMap::new(),
            links: BTreeMap::new(),
            cache_budget: CacheBudget::default(),
            challenges: BTreeMap::new(),
            max_bps,
            repair,
            tokens: 2400.0,
            updated: Instant::now(),
            cursor: 0,
            invalid_packets: 0,
            socket_dropped: 0,
            idle_retired: 0,
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
    pub(crate) async fn recv(
        &mut self,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, Option<Source>)> {
        self.receiver.recv(&self.socket, buffer).await
    }
    pub(crate) fn try_recv(
        &mut self,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, Option<Source>)> {
        self.receiver.try_recv(&self.socket, buffer)
    }
    pub fn connected(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.peers.keys().copied()
    }
    pub fn has_peer(&self, peer: NodeId) -> bool {
        self.peers.contains_key(&peer)
    }
    pub(crate) fn set_denied(&mut self, denied: BTreeSet<NodeId>) {
        for &node in &denied {
            self.disconnect(node);
        }
        self.denied = denied;
    }
    pub(crate) fn discard_queued(&mut self) {
        for link in self.links.values_mut() {
            link.discard_queued();
        }
    }
    /// Overlay application/relay traffic only, not LSA, ACK, PMTU or keepalive.
    pub fn used(&mut self, peer: NodeId, now: Instant) {
        if let Some(p) = self.peers.get_mut(&peer) {
            p.used = now;
        }
    }
    pub fn idle_candidates(&self, now: Instant, idle: Duration) -> Vec<NodeId> {
        let mut candidates: Vec<_> = self
            .peers
            .iter()
            .filter(|(id, p)| {
                !self.neighbors.is_configured(**id) && now.saturating_duration_since(p.used) >= idle
            })
            .map(|(&id, p)| (p.used, id))
            .collect();
        candidates.sort_unstable();
        candidates.into_iter().map(|(_, id)| id).collect()
    }
    fn disconnect(&mut self, peer: NodeId) {
        self.peers.remove(&peer);
        self.neighbors.disconnect(peer);
        self.crypto.forget(peer);
        self.challenges.remove(&peer);
        self.flights.retain(|_, f| f.peer != peer);
        self.links.retain(|_, l| l.scope().peer != peer);
    }
    /// Caller must first prove a lower-ranked, usable alternative overlay path.
    pub async fn retire_idle(
        &mut self,
        peer: NodeId,
        idle: Duration,
        now: Instant,
    ) -> Result<Option<Event>> {
        if self.neighbors.is_configured(peer)
            || self
                .peers
                .get(&peer)
                .is_none_or(|p| now.saturating_duration_since(p.used) < idle)
        {
            return Ok(None);
        }
        let endpoint = self.peers[&peer].endpoint;
        if let Some(session) = self.crypto.active_session(peer) {
            let notice = self.crypto.encrypt_session(session, &[RETIRE])?;
            // Best effort. A lost notice uses the existing six-second liveness
            // timeout; it does not allocate a second reliable-close protocol.
            let local = self.peers.get(&peer).and_then(|p| p.local);
            self.transmit(endpoint, local, &notice, now).await?;
        }
        self.disconnect(peer);
        self.idle_retired += 1;
        Ok(Some(Event::Disconnected(peer)))
    }
    pub fn status(&self, now: Instant) -> Vec<PeerStatus> {
        self.peers
            .iter()
            .map(|(&node, p)| PeerStatus {
                node,
                endpoint: p.endpoint,
                key_epoch: self.crypto.active_session(node),
                pmtu: p.pmtu.status(),
                idle_ms: now.saturating_duration_since(p.seen).as_millis(),
                traffic_idle_ms: now.saturating_duration_since(p.used).as_millis(),
                link: self
                    .crypto
                    .active_session(node)
                    .and_then(|id| self.links.get(&id))
                    .map(|link| link.stats(&p.control))
                    .unwrap_or_default(),
            })
            .collect()
    }
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.max_bps as f64 / 8.0).min(64_000.0);
        self.updated = now;
    }
    pub(crate) fn send_delay(&self, now: Instant) -> Option<Duration> {
        let path = self
            .links
            .values()
            .filter_map(|link| {
                let peer = self.peers.get(&link.scope().peer)?;
                link.send_delay(&peer.control, now)
            })
            .min()?;
        let rate = self.max_bps as f64 / 8.0;
        let tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * rate)
            .min(64_000.0);
        // flush requires one maximum datagram's global allowance before polling.
        let global = Duration::from_secs_f64((((MAX_UDP + 48) as f64 - tokens) / rate).max(0.0));
        Some(path.max(global))
    }
    async fn transmit(
        &mut self,
        endpoint: SocketAddr,
        local: Option<Source>,
        bytes: &[u8],
        now: Instant,
    ) -> Result<()> {
        ensure!(bytes.len() <= MAX_UDP, "UDP payload exceeds underlay MTU");
        self.refill(now);
        let cost = (bytes.len() + 48) as f64;
        if self.tokens < cost {
            self.socket_dropped += 1;
            return Ok(());
        }
        self.tokens -= cost;
        self.send_admitted(endpoint, local, bytes, now).await
    }
    async fn send_admitted(
        &mut self,
        endpoint: SocketAddr,
        local: Option<Source>,
        bytes: &[u8],
        now: Instant,
    ) -> Result<()> {
        let mut result = socket::send(&self.socket, bytes, endpoint, local).await;
        if local.is_some()
            && result
                .as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::AddrNotAvailable)
        {
            // DHCP may remove the old local address while the peer is alive.
            // Forget only this invalid affinity, then let the kernel choose again.
            for p in self.peers.values_mut().filter(|p| p.local == local) {
                p.local = None;
            }
            for f in self.flights.values_mut().filter(|f| f.local == local) {
                f.local = None;
            }
            result = self.socket.send_to(bytes, endpoint).await;
        }
        match result {
            Ok(_) => (),
            Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
                self.socket_dropped += 1;
                // Exact destination of this failed send, never a different peer
                // sharing an unconnected UDP socket. A probe will revalidate.
                for peer in self.peers.values_mut().filter(|p| p.endpoint == endpoint) {
                    peer.pmtu.too_big(bytes.len(), now);
                }
            }
            Err(error) if is_path_error(&error) => {
                self.socket_dropped += 1;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    async fn transmit_batch(&mut self, packets: &[socket::Datagram], now: Instant) -> Result<()> {
        let mut sent = 0;
        while sent < packets.len() {
            match socket::send_batch(&self.socket, &packets[sent..], self.gso).await {
                Ok(n) if n > 0 => sent += n,
                result => {
                    // GSO is optional. Unsupported kernel/device paths fall back for
                    // this socket, without changing wire format or source affinity.
                    if result.as_ref().is_err_and(|e| {
                        matches!(
                            e.raw_os_error(),
                            Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::EIO)
                        )
                    }) {
                        self.gso = false;
                    }
                    // A failed sendmsg accepts no datagrams. Retry only the first
                    // unsent packet through PMTU/DHCP handling; do not charge twice.
                    let p = &packets[sent];
                    self.send_admitted(p.endpoint, p.local, &p.bytes, now)
                        .await?;
                    sent += 1;
                }
            }
        }
        Ok(())
    }
    pub async fn connect(
        &mut self,
        peer: NodeId,
        endpoint: SocketAddr,
        now: Instant,
    ) -> Result<()> {
        self.start_handshake(peer, endpoint, now, false).await
    }
    /// Candidate races use distinct Noise sessions, never one flight whose
    /// accepted source address changes in response to unauthenticated packets.
    pub(crate) async fn connect_candidate(
        &mut self,
        peer: NodeId,
        endpoint: SocketAddr,
        now: Instant,
    ) -> Result<()> {
        self.start_handshake(peer, endpoint, now, true).await
    }
    async fn start_handshake(
        &mut self,
        peer: NodeId,
        endpoint: SocketAddr,
        now: Instant,
        candidate: bool,
    ) -> Result<()> {
        ensure!(!self.denied.contains(&peer), "peer denied locally");
        let endpoint = canonical_address(endpoint);
        ensure!(
            !endpoint.ip().is_unspecified()
                && !endpoint.ip().is_multicast()
                && endpoint.port() != 0,
            "invalid peer endpoint"
        );
        self.neighbors.check_capacity(peer)?;
        if self.flights.iter().any(|(&id, f)| {
            f.peer == peer && f.endpoint == endpoint && self.crypto.pending_session(id)
        }) {
            return Ok(());
        }
        ensure!(self.flights.len() < 128, "handshake address capacity");
        let local = self
            .peers
            .get(&peer)
            .filter(|p| p.endpoint == endpoint)
            .and_then(|p| p.local);
        let initiation = if candidate {
            self.crypto.begin_candidate(peer, now)?
        } else {
            self.crypto.begin(peer, now)?
        };
        if let Some(bytes) = initiation {
            let session = Packet::parse(&bytes)?.session;
            self.flights.insert(
                session,
                Flight {
                    peer,
                    local,
                    endpoint,
                    created: now,
                },
            );
            self.transmit(endpoint, local, &bytes, now).await?;
        }
        Ok(())
    }
    pub(crate) fn supports_compact(&self, peer: NodeId) -> bool {
        self.crypto
            .active_session(peer)
            .and_then(|id| self.links.get(&id))
            .is_some_and(Link::supports_compact)
    }
    pub(crate) fn can_send(&self, peer: NodeId, bytes: usize) -> Result<bool> {
        let id = self
            .crypto
            .active_session(peer)
            .context("peer not connected")?;
        let link = self.links.get(&id).context("missing peer link")?;
        let path = self.peers.get(&peer).context("missing path")?;
        Ok(link.can_enqueue(bytes, &path.control))
    }
    pub fn send(&mut self, peer: NodeId, message: Message, now: Instant) -> Result<()> {
        ensure!(message.kind != INTERNAL, "reserved message kind");
        self.enqueue(peer, message, now)
    }
    fn enqueue(&mut self, peer: NodeId, message: Message, now: Instant) -> Result<()> {
        let id = self
            .crypto
            .active_session(peer)
            .context("peer not connected")?;
        self.links
            .get_mut(&id)
            .context("missing peer link")?
            .enqueue(
                message,
                now,
                &self.peers.get(&peer).context("missing path")?.control,
            )
    }
    /// Invalid packets are counted and discarded, not propagated as daemon failures.
    pub(crate) async fn receive(
        &mut self,
        bytes: &[u8],
        from: SocketAddr,
        local: Option<Source>,
        now: Instant,
    ) -> Vec<Event> {
        // Authentication can commit a connection before the enclosed payload
        // is parsed. Packet failure must not hide that state change from Engine.
        // This vector belongs to one receive, not a persistent event queue.
        let mut events = vec![];
        if self
            .handle(bytes, canonical_address(from), local, now, &mut events)
            .await
            .is_err()
        {
            self.invalid_packets += 1;
        }
        events
    }
    async fn handle(
        &mut self,
        bytes: &[u8],
        from: SocketAddr,
        local: Option<Source>,
        now: Instant,
        events: &mut Vec<Event>,
    ) -> Result<()> {
        ensure!(bytes.len() <= MAX_UDP, "oversized UDP packet");
        let packet = Packet::parse(bytes)?;
        ensure!(packet.scope == LINK_SCOPE, "wrong UDP scope");
        let session = packet.session;
        if packet.kind != DATA {
            return self.handshake(bytes, from, local, now, events).await;
        }
        // Check the pinned flight BEFORE decrypt/replay bookkeeping. A valid
        // proof copied to another endpoint cannot activate a provisional key.
        if self.crypto.awaiting_confirmation(session) {
            let flight = self
                .flights
                .get(&session)
                .context("untracked provisional key")?;
            ensure!(flight.endpoint == from, "confirmation endpoint changed");
        }
        let (peer, plaintext) = self.crypto.decrypt(bytes, now)?;
        if self.crypto.confirm_authenticated(session, now)?.is_some() {
            events.extend(self.established(peer, session, from, local, now)?);
        }
        let endpoint = self.peers.get(&peer).context("unadmitted peer")?.endpoint;
        if plaintext.first() == Some(&255) {
            events.extend(
                self.path_control(peer, session, &plaintext, from, local, now)
                    .await?,
            );
            return Ok(());
        }
        if endpoint != from {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.challenges.entry(peer) {
                let token = wire::random_id()?;
                entry.insert(Challenge {
                    endpoint: from,
                    local,
                    token,
                    expires: now + Duration::from_secs(2),
                });
                let mut challenge = vec![255, 1];
                challenge.extend_from_slice(&token.to_be_bytes());
                let encrypted = self.crypto.encrypt_session(session, &challenge)?;
                self.transmit(from, local, &encrypted, now).await?;
            }
            return Ok(());
        }
        if plaintext == [RETIRE] {
            if self.crypto.active_session(peer) == Some(session) {
                self.disconnect(peer);
                events.push(Event::Disconnected(peer));
            }
            return Ok(());
        }
        if plaintext.first() == Some(&pmtu::TAG) {
            let control = pmtu::Control::decode(&plaintext)?;
            let current = self.crypto.active_session(peer) == Some(session);
            if current {
                self.local_source(peer, local, now);
            }
            match control {
                pmtu::Control::Probe { reply } => {
                    // Crossed rekeys can select different outgoing epochs.
                    // A retained, authenticated receive epoch can still be the
                    // peer's active send epoch: echo its probe in that epoch,
                    // without modifying our current path/source or PMTU state.
                    let encrypted = self.crypto.encrypt_session(session, &reply)?;
                    self.transmit(from, local, &encrypted, now).await?;
                }
                pmtu::Control::Ack { token, size } => {
                    if !current {
                        return Ok(());
                    }
                    self.peers
                        .get_mut(&peer)
                        .expect("admitted peer")
                        .pmtu
                        .acknowledge(token, size, now);
                }
            }
            self.peers.get_mut(&peer).expect("admitted peer").seen = now;
            return Ok(());
        }
        let messages = self
            .links
            .get_mut(&session)
            .context("unknown link epoch")?
            .receive_authenticated(
                &plaintext,
                now,
                &mut self.peers.get_mut(&peer).context("missing path")?.control,
            )?;
        if self.crypto.active_session(peer) == Some(session) {
            self.local_source(peer, local, now);
        }
        self.peers.get_mut(&peer).expect("admitted peer").seen = now;
        for message in messages {
            if message.kind != INTERNAL {
                events.push(Event::Message(peer, message));
                continue;
            }
            match message.payload.as_slice() {
                // Explicit, authenticated per-key-epoch capability v2: compact
                // single sources and implicit identities for terminal DATA.
                // Old GGB3 ignores these INTERNAL opcodes. Never infer support
                // from PMTU, a node record, or a previous key epoch.
                [op @ (2 | 3), COMPACT_VERSION] => {
                    let link = self.links.get_mut(&session).context("capability epoch")?;
                    link.enable_compact();
                    if *op == 2 {
                        let _ = link.enqueue(
                            Message {
                                kind: INTERNAL,
                                payload: vec![3, COMPACT_VERSION],
                            },
                            now,
                            &self.peers[&peer].control,
                        );
                    }
                }
                [0] => {
                    let mut payload = vec![1];
                    payload.extend_from_slice(from.to_string().as_bytes());
                    let _ = self.enqueue(
                        peer,
                        Message {
                            kind: INTERNAL,
                            payload,
                        },
                        now,
                    );
                }
                [1, address @ ..]
                    if address.len() <= 64 && self.crypto.active_session(peer) == Some(session) =>
                {
                    if let Ok(address) = std::str::from_utf8(address)?.parse() {
                        events.push(Event::ObservedEndpoint {
                            observer: peer,
                            address,
                        });
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
    async fn handshake(
        &mut self,
        bytes: &[u8],
        from: SocketAddr,
        local: Option<Source>,
        now: Instant,
        events: &mut Vec<Event>,
    ) -> Result<()> {
        let packet = Packet::parse(bytes)?;
        let session = packet.session;
        let peer = if packet.kind == HS1 {
            ensure!(packet.body.len() == 256, "handshake length");
            let peer = NodeId::from_bytes(packet.body[..32].try_into()?)?;
            ensure!(!self.denied.contains(&peer), "peer denied locally");
            self.neighbors.check_capacity(peer)?;
            ensure!(
                self.flights.len() < 128 || self.flights.contains_key(&session),
                "handshake path capacity"
            );
            peer
        } else {
            self.flights
                .get(&session)
                .context("unsolicited handshake")?
                .peer
        };
        if let Some(flight) = self.flights.get(&session) {
            ensure!(
                flight.endpoint == from && flight.peer == peer,
                "handshake endpoint changed"
            );
        }
        let result = self.crypto.receive_handshake(bytes, Some(peer), now)?;
        self.flights.entry(session).or_insert(Flight {
            peer,
            local,
            endpoint: from,
            created: now,
        });
        if let Some(flight) = self.flights.get_mut(&session) {
            flight.local = local;
        }
        if let Some(peer) = result.established {
            events.extend(self.established(peer, session, from, local, now)?);
        }
        // The crypto transition has already committed. A local send failure
        // must not lose admission; the final flight remains cached for retry.
        if let Some(reply) = result.reply {
            self.transmit(from, local, &reply, now).await?;
        }
        Ok(())
    }
    fn established(
        &mut self,
        peer: NodeId,
        session: u64,
        from: SocketAddr,
        local: Option<Source>,
        now: Instant,
    ) -> Result<Vec<Event>> {
        let mut events = vec![];
        if self.crypto.active_session(peer) != Some(session)
            && self
                .peers
                .get(&peer)
                .is_some_and(|path| path.endpoint != from)
        {
            // A delayed proof for an older candidate cannot roll the chosen path back.
            return Ok(events);
        }
        if let Err(error) = self.neighbors.connect_authenticated(peer) {
            self.crypto.forget(peer);
            return Err(error);
        }
        for cancelled in self.crypto.cancel_initiated(peer) {
            self.flights.remove(&cancelled);
        }
        // Keep simultaneous-open keys on this path, but cancel provisional
        // keys on losing candidate endpoints as well as unfinished Noise flights.
        let losing: Vec<_> = self
            .flights
            .iter()
            .filter(|(id, f)| {
                f.peer == peer && f.endpoint != from && self.crypto.awaiting_confirmation(**id)
            })
            .map(|(&id, _)| id)
            .collect();
        for id in losing {
            self.crypto.discard_unconfirmed(id);
            self.flights.remove(&id);
        }
        let previous = self.peers.remove(&peer);
        let new = previous.is_none();
        let used = previous.as_ref().map_or(now, |p| p.used);
        let (mut pmtu, control) = match previous {
            Some(p) if p.endpoint == from && p.local == local => (p.pmtu, p.control),
            _ => {
                // No FEC/cache or timestamp history crosses an authenticated
                // endpoint change. The new path starts with one fresh budget.
                self.links.retain(|_, link| link.scope().peer != peer);
                (pmtu::PathMtu::new(now), Controller::new(self.max_bps, now))
            }
        };
        pmtu.rekey(now);
        let datagram_limit = pmtu.limit();
        self.peers.insert(
            peer,
            Peer {
                endpoint: from,
                local,
                seen: now,
                heartbeat: now,
                used,
                pmtu,
                control,
                load: (0, false),
            },
        );
        let scope = FecScope {
            peer,
            path_epoch: session,
            key_epoch: session,
            direction: 0,
        };
        let mut link = Link::new(scope, now, self.repair);
        link.share_cache_budget(self.cache_budget.clone());
        link.set_datagram_limit(datagram_limit, now, &self.peers[&peer].control)?;
        self.links.insert(session, link);
        if new {
            events.push(Event::Connected(peer));
        }
        Ok(events)
    }
    async fn path_control(
        &mut self,
        peer: NodeId,
        session: u64,
        bytes: &[u8],
        from: SocketAddr,
        local: Option<Source>,
        now: Instant,
    ) -> Result<Vec<Event>> {
        ensure!(bytes.len() == 10, "invalid path control");
        match bytes[1] {
            1 => {
                let mut reply = bytes.to_vec();
                reply[1] = 2;
                let encrypted = self.crypto.encrypt_session(session, &reply)?;
                self.transmit(from, local, &encrypted, now).await?;
            }
            2 => {
                let token = u64::from_be_bytes(bytes[2..].try_into()?);
                if self.challenges.get(&peer).is_some_and(|c| {
                    c.endpoint == from && c.local == local && c.token == token && now < c.expires
                }) {
                    self.challenges.remove(&peer);
                    let p = self.peers.get_mut(&peer).context("expired peer")?;
                    p.endpoint = from;
                    p.local = local;
                    p.seen = now;
                    // The subsequent handshake sees this new endpoint pair.
                    // Reset here, before it can be mistaken for a same-path rekey.
                    p.pmtu = pmtu::PathMtu::new(now);
                    p.control = Controller::new(self.max_bps, now);
                    // A new path gets a new key/FEC epoch; never mix shards from
                    // different paths. In-flight IP packets may be dropped here.
                    self.links.retain(|_, link| link.scope().peer != peer);
                    self.crypto.cancel_pending(peer);
                    self.flights.retain(|_, flight| flight.peer != peer);
                    self.connect(peer, from, now).await?;
                    return Ok(vec![Event::EndpointChanged(peer, from)]);
                }
            }
            _ => (),
        }
        Ok(vec![])
    }
    fn local_source(&mut self, peer: NodeId, local: Option<Source>, now: Instant) {
        if let Some(p) = self.peers.get_mut(&peer)
            && local.is_some()
            && p.local != local
        {
            p.local = local;
            p.pmtu = pmtu::PathMtu::new(now);
            p.control = Controller::new(self.max_bps, now);
            for link in self
                .links
                .values_mut()
                .filter(|link| link.scope().peer == peer)
            {
                link.reset_clock();
            }
        }
    }
    pub async fn tick(&mut self, now: Instant) -> Result<Vec<Event>> {
        self.refill(now);
        let mut events = vec![];
        self.flights
            .retain(|_, f| now.saturating_duration_since(f.created) < Duration::from_secs(12));
        self.challenges.retain(|_, c| now < c.expires);
        for (peer, bytes) in self.crypto.maintenance(now) {
            let session = Packet::parse(&bytes)?.session;
            if let Some(f) = self.flights.get(&session)
                && f.peer == peer
            {
                self.transmit(f.endpoint, f.local, &bytes, now).await?;
            }
        }
        let peers: Vec<_> = self.peers.keys().copied().collect();
        for peer in peers {
            let p = self.peers.get(&peer).expect("peer snapshot");
            if now.saturating_duration_since(p.seen) >= DEAD_AFTER {
                self.disconnect(peer);
                events.push(Event::Disconnected(peer));
                continue;
            }
            let endpoint = p.endpoint;
            let heartbeat_due = now.saturating_duration_since(p.heartbeat) >= KEEPALIVE;
            if let Some(session) = self.crypto.active_session(peer) {
                let probe = if self.tokens >= (MAX_UDP + 48) as f64 {
                    self.peers
                        .get_mut(&peer)
                        .expect("live peer")
                        .pmtu
                        .poll(now)?
                } else {
                    None
                };
                if let Some(probe) = probe {
                    let encrypted = self.crypto.encrypt_session(session, &probe)?;
                    self.transmit(
                        endpoint,
                        self.peers.get(&peer).and_then(|p| p.local),
                        &encrypted,
                        now,
                    )
                    .await?;
                }
                let limit = self.peers[&peer].pmtu.limit();
                if let Some(link) = self.links.get_mut(&session) {
                    link.set_datagram_limit(limit, now, &self.peers[&peer].control)?;
                }
            }
            if heartbeat_due {
                if !self.supports_compact(peer) {
                    let _ = self.enqueue(
                        peer,
                        Message {
                            kind: INTERNAL,
                            payload: vec![2, COMPACT_VERSION],
                        },
                        now,
                    );
                }
                let _ = self.enqueue(
                    peer,
                    Message {
                        kind: INTERNAL,
                        payload: vec![0],
                    },
                    now,
                );
                self.peers.get_mut(&peer).expect("live peer").heartbeat = now;
            }
            if self
                .crypto
                .active_session(peer)
                .is_none_or(|id| !self.links.contains_key(&id))
                || self
                    .crypto
                    .session_age(peer, now)
                    .is_some_and(|age| age >= REKEY_AFTER)
            {
                // Admission can be temporarily saturated; keep the working old
                // session and retry next tick rather than terminating the daemon.
                let _ = self.connect(peer, endpoint, now).await;
            }
        }
        self.links.retain(|id, _| self.crypto.contains_session(*id));
        self.flush(now).await?;
        Ok(events)
    }

    /// Data-plane service can run on I/O progress, without repeating handshake,
    /// discovery or liveness maintenance. Every packet still pays both pacers.
    pub(crate) async fn flush(&mut self, now: Instant) -> Result<()> {
        self.refill(now);
        // Each authenticated path has ONE estimator, pacer and repair ledger,
        // including retained receive epochs. Maintain it once with total load.
        for path in self.peers.values_mut() {
            path.load = (0, false);
        }
        for link in self.links.values() {
            let path = self
                .peers
                .get_mut(&link.scope().peer)
                .context("link without path")?;
            let (bytes, pending) = link.load();
            path.load.0 += bytes;
            path.load.1 |= pending;
        }
        for path in self.peers.values_mut() {
            path.control.tick(now, path.load.0, path.load.1);
        }
        let ids: Vec<_> = self.links.keys().copied().collect();
        if ids.is_empty() {
            return Ok(());
        }
        // Round robin, one datagram per turn; local and relay messages share this cap.
        let mut idle = 0;
        let mut batch = Vec::with_capacity(socket::SEND_BATCH);
        for _ in 0..256 {
            if self.tokens < (MAX_UDP + 48) as f64 {
                break;
            }
            self.cursor %= ids.len();
            let id = ids[self.cursor];
            self.cursor += 1;
            let link = self.links.get_mut(&id).expect("link snapshot");
            let peer = link.scope().peer;
            // Also constrain finite retransmissions from an old receive epoch,
            // without scanning all links once per peer on every timer tick.
            let path = self.peers.get_mut(&peer).context("link without path")?;
            link.set_datagram_limit(path.pmtu.limit(), now, &path.control)?;
            let Some(bytes) = link.poll_one(now, &mut path.control)? else {
                idle += 1;
                if idle >= ids.len() {
                    break;
                }
                continue;
            };
            idle = 0;
            let encrypted = self.crypto.encrypt_session(id, &bytes)?;
            if let Some(p) = self.peers.get(&peer) {
                self.tokens -= (encrypted.len() + 48) as f64;
                batch.push(socket::Datagram {
                    bytes: encrypted,
                    endpoint: p.endpoint,
                    local: p.local,
                    // Small/black-holed paths need conservative packet-at-a-time
                    // delivery: virtual-router length filters can see a GSO skb
                    // before segmentation, even when each segment fits the PMTU.
                    // A single-datagram probe does not validate that aggregate.
                    gso: matches!(p.pmtu.limit(), wire::BASE_UDP | MAX_UDP),
                });
                if batch.len() == socket::SEND_BATCH {
                    self.transmit_batch(&batch, now).await?;
                    batch.clear();
                }
            }
        }
        self.transmit_batch(&batch, now).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
