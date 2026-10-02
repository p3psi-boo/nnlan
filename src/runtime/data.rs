use super::*;
use crate::transport::wire::{DATA, TRACE, TRACE_REPLY};
use diagnostics::{Ping, Probe, Reply, Trace};

impl Engine {
    pub(super) fn forward(&mut self, envelope: Envelope, now: Instant) -> Result<()> {
        ensure!(
            envelope.hops > 0 && envelope.hops <= 32,
            "overlay hop limit"
        );
        let path = self
            .control
            .path(envelope.destination)
            .context("no overlay route")?;
        let next = *path.get(1).context("cannot forward to local node")?;
        self.forward_via(envelope, next, now)
    }
    fn forward_via(&mut self, envelope: Envelope, next: NodeId, now: Instant) -> Result<()> {
        let message = if envelope.is_direct_data(self.identity.node_id(), next)
            && self.transport.supports_compact(next)
        {
            Message {
                kind: DIRECT_DATA_MESSAGE,
                payload: envelope.body,
            }
        } else {
            Message {
                kind: ENVELOPE_MESSAGE,
                payload: envelope.encode(),
            }
        };
        self.transport.send(next, message, now)?;
        self.transport.used(next, now);
        Ok(())
    }
    pub(super) async fn envelope(&mut self, mut envelope: Envelope, now: Instant) -> Result<()> {
        ensure!(
            envelope.hops > 0 && envelope.hops <= 32 && self.control.trusted(envelope.source),
            "untrusted source or hop limit"
        );
        let local = self.identity.node_id();
        if envelope.kind == TRACE {
            ensure!(envelope.body.len() <= 2048, "trace length");
            let probe: Probe = serde_json::from_slice(&envelope.body)?;
            probe.verify(unix_time()?)?;
            ensure!(
                probe.origin == envelope.source
                    && probe.target == envelope.destination
                    && envelope.hops <= probe.ttl,
                "trace envelope binding"
            );
            if envelope.hops == 1 || envelope.destination == local {
                let reply = Reply::issue(&self.identity, &probe)?;
                return self.forward(
                    Envelope {
                        source: local,
                        destination: probe.origin,
                        hops: 32,
                        kind: TRACE_REPLY,
                        body: serde_json::to_vec(&reply)?,
                    },
                    now,
                );
            }
        }
        if envelope.destination != local {
            ensure!(self.config.relay, "relay disabled");
            ensure!(envelope.hops > 1, "overlay hop limit exhausted");
            envelope.hops -= 1;
            self.forward(envelope, now)?;
            self.forwarded += 1;
            return Ok(());
        }
        match envelope.kind {
            DATA => {
                // The authenticated previous hop vouches for the source identity.
                // All relays are trusted members; there is no nested Noise session.
                let peer = envelope.source;
                let plain = envelope.body;
                ensure!(!plain.is_empty(), "empty overlay data");
                match plain[0] {
                    0 => {
                        let packet = &plain[1..];
                        let (source, destination) = tunnel::ip_addresses(packet)?;
                        self.validate_received_ip(peer, source, destination)?;
                        if let Some(tunnel) = &mut self.tunnel {
                            ensure!(
                                packet.len() <= usize::from(self.config.tun.mtu),
                                "remote packet exceeds local TUN MTU"
                            );
                            tunnel.send(packet).await?;
                            self.ip_received += 1;
                        }
                    }
                    1 => {
                        ensure!((9..=16_393).contains(&plain.len()), "ping length");
                        let mut reply = plain;
                        reply[0] = 2;
                        self.send_data(peer, reply, now).await?;
                    }
                    2 => {
                        ensure!(plain.len() >= 9, "pong length");
                        let id = u64::from_be_bytes(plain[1..9].try_into()?);
                        if self.diagnostics.pings.get(&id).is_some_and(|p| {
                            p.target == peer && p.hash == blake3::hash(&plain[9..])
                        }) {
                            let ping = self.diagnostics.pings.remove(&id).expect("verified ping");
                            let _=ping.reply.send(json!({"target":peer,"bytes":ping.bytes,"rtt_ms":now.saturating_duration_since(ping.started).as_secs_f64()*1000.0,"hop_encrypted":true}));
                        }
                    }
                    _ => anyhow::bail!("unknown overlay data kind"),
                }
            }
            TRACE_REPLY => {
                ensure!(envelope.body.len() <= 2048, "trace reply length");
                let reply: Reply = serde_json::from_slice(&envelope.body)?;
                reply.verify(unix_time()?)?;
                ensure!(
                    reply.node == envelope.source && reply.origin == local,
                    "trace reply source binding"
                );
                self.diagnostics.receive_trace(reply, now);
            }
            _ => anyhow::bail!("unknown envelope kind"),
        }
        Ok(())
    }
    async fn send_data(&mut self, peer: NodeId, body: Vec<u8>, now: Instant) -> Result<()> {
        ensure!(
            peer != self.identity.node_id() && self.control.trusted(peer),
            "overlay peer identity"
        );
        self.forward(
            Envelope {
                source: self.identity.node_id(),
                destination: peer,
                hops: 32,
                kind: DATA,
                body,
            },
            now,
        )?;
        self.try_direct(peer, now).await;
        Ok(())
    }
    /// Resolve the current policy/path on every retry. No resolved route is
    /// retained across membership revocation, exit changes, PMTU or rekey.
    fn ip_path(&mut self, packet: &[u8]) -> Result<(NodeId, NodeId)> {
        let (source, destination) = tunnel::ip_addresses(packet)?;
        let peer = self.outbound_ip_peer(source, destination)?;
        ensure!(
            peer != self.identity.node_id() && self.control.trusted(peer),
            "overlay peer identity"
        );
        let path = self.control.path(peer).context("no overlay route")?;
        let next = *path.get(1).context("cannot forward to local node")?;
        Ok((peer, next))
    }
    fn ip_capacity(&self, peer: NodeId, next: NodeId, bytes: usize) -> Result<bool> {
        let header = if peer == next && self.transport.supports_compact(next) {
            0
        } else {
            wire::ENVELOPE_HEADER
        };
        self.transport.can_send(next, bytes + 1 + header)
    }
    /// False returns the packet to the ingress flow; no sequence or FEC group
    /// allocation has occurred. UDP processing remains with the event loop.
    pub(super) async fn send_ip(&mut self, packet: &[u8], now: Instant) -> Result<bool> {
        let (peer, next) = self.ip_path(packet)?;
        if !self.ip_capacity(peer, next, packet.len())? {
            return Ok(false);
        }
        let mut plain = Vec::with_capacity(packet.len() + 1);
        plain.push(0);
        plain.extend_from_slice(packet);
        self.forward_via(
            Envelope {
                source: self.identity.node_id(),
                destination: peer,
                hops: 32,
                kind: DATA,
                body: plain,
            },
            next,
            now,
        )?;
        self.try_direct(peer, now).await;
        self.ip_sent += 1;
        Ok(true)
    }
    pub(super) async fn drain_ingress(&mut self) -> bool {
        let started = Instant::now();
        let drops = self.ingress.stats.dropped();
        let mut blocked = [false; ingress::FLOWS];
        let mut progress = false;
        let mut reschedule = false;
        for index in 0..128 {
            let Some(packet) = self.ingress.dequeue(Instant::now(), &blocked) else {
                break;
            };
            match self.send_ip(&packet.bytes, Instant::now()).await {
                Ok(false) => self.ingress.defer(packet, &mut blocked),
                Ok(true) => progress = true,
                Err(error) => {
                    self.dropped += 1;
                    progress = true;
                    if self.dropped <= 8 || self.dropped.is_power_of_two() {
                        eprintln!("TUN outbound dropped ({}): {error:#}", self.dropped);
                    }
                }
            }
            if index == 127 || started.elapsed() >= Duration::from_micros(100) {
                reschedule = progress && !self.ingress.is_empty();
                break;
            }
        }
        self.dropped += self.ingress.stats.dropped() - drops;
        // Never spin on a full link/cache: UDP feedback or the existing tick
        // reopens admission. Ready work gets another bounded, fair select turn.
        reschedule
    }
    pub(super) fn start_trace(
        &mut self,
        target: &str,
        reply: oneshot::Sender<Value>,
        now: Instant,
    ) {
        let preparation = (|| -> Result<_> {
            ensure!(self.diagnostics.traces.len() < 16, "trace capacity");
            let target = self.control.resolve(target)?;
            let path = self.control.path(target).context("no overlay route")?;
            let id = wire::random_id()?;
            let hops = (path.len().saturating_sub(1) + 2).min(32) as u8;
            Ok((target, id, hops))
        })();
        let (target, id, max_hops) = match preparation {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(json!({"error":e.to_string()}));
                return;
            }
        };
        if target == self.identity.node_id() {
            let _ = reply.send(json!({"target":target,"complete":true,"hops":[]}));
            return;
        }
        self.diagnostics.traces.insert(
            id,
            Trace {
                target,
                started: now,
                max_hops,
                hops: BTreeMap::new(),
                done: None,
                reply,
            },
        );
        let result = (|| -> Result<()> {
            for ttl in 1..=max_hops {
                let probe = Probe::issue(&self.identity, target, id, ttl, unix_time()?)?;
                self.forward(
                    Envelope {
                        source: self.identity.node_id(),
                        destination: target,
                        hops: ttl,
                        kind: TRACE,
                        body: serde_json::to_vec(&probe)?,
                    },
                    now,
                )?;
            }
            Ok(())
        })();
        if let Err(e) = result
            && let Some(trace) = self.diagnostics.traces.remove(&id)
        {
            let _ = trace.reply.send(json!({"error":e.to_string()}));
        }
    }
    pub(super) async fn start_ping(
        &mut self,
        target: &str,
        size: usize,
        reply: oneshot::Sender<Value>,
        now: Instant,
    ) {
        let preparation = (|| -> Result<_> {
            ensure!(
                self.diagnostics.pings.len() < 16 && size <= 16_384,
                "ping capacity/size"
            );
            let target = self.control.resolve(target)?;
            let id = wire::random_id()?;
            let mut payload = vec![0; size];
            getrandom::fill(&mut payload).map_err(|e| anyhow::anyhow!("ping randomness: {e}"))?;
            Ok((target, id, payload))
        })();
        let (target, id, payload) = match preparation {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(json!({"error":e.to_string()}));
                return;
            }
        };
        if target == self.identity.node_id() {
            let _ = reply.send(json!({"target":target,"bytes":size,"rtt_ms":0}));
            return;
        }
        self.diagnostics.pings.insert(
            id,
            Ping {
                target,
                started: now,
                hash: blake3::hash(&payload),
                bytes: size,
                reply,
            },
        );
        let mut plain = vec![1];
        plain.extend_from_slice(&id.to_be_bytes());
        plain.extend_from_slice(&payload);
        if let Err(e) = self.send_data(target, plain, now).await
            && let Some(ping) = self.diagnostics.pings.remove(&id)
        {
            let _ = ping.reply.send(json!({"error":e.to_string()}));
        }
    }
}
