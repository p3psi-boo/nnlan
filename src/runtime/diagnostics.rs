use crate::identity::{Identity, NodeId};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

// Frozen protocol domain: product renaming must preserve addresses and peer compatibility.
const PROBE_DOMAIN: &str = "ggbond.trace-probe.v1";
const REPLY_DOMAIN: &str = "ggbond.trace-reply.v1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub id: u64,
    pub origin: NodeId,
    pub target: NodeId,
    pub ttl: u8,
    pub expires: u64,
    pub signature: Vec<u8>,
}
impl Probe {
    fn payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            self.id,
            self.origin,
            self.target,
            self.ttl,
            self.expires,
        ))?)
    }
    pub fn issue(identity: &Identity, target: NodeId, id: u64, ttl: u8, now: u64) -> Result<Self> {
        let mut probe = Self {
            id,
            origin: identity.node_id(),
            target,
            ttl,
            expires: now + 5,
            signature: vec![],
        };
        probe.signature = identity.sign(PROBE_DOMAIN, &probe.payload()?).to_vec();
        Ok(probe)
    }
    pub fn verify(&self, now: u64) -> Result<()> {
        ensure!(
            self.ttl > 0 && self.ttl <= 32 && self.expires >= now && self.expires <= now + 5,
            "trace probe bounds"
        );
        self.origin.verify(
            PROBE_DOMAIN,
            &self.payload()?,
            self.signature
                .as_slice()
                .try_into()
                .context("trace signature")?,
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub id: u64,
    pub origin: NodeId,
    pub target: NodeId,
    pub ttl: u8,
    pub node: NodeId,
    pub done: bool,
    pub expires: u64,
    pub signature: Vec<u8>,
}
impl Reply {
    fn payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            self.id,
            self.origin,
            self.target,
            self.ttl,
            self.node,
            self.done,
            self.expires,
        ))?)
    }
    pub fn issue(identity: &Identity, probe: &Probe) -> Result<Self> {
        let mut reply = Self {
            id: probe.id,
            origin: probe.origin,
            target: probe.target,
            ttl: probe.ttl,
            node: identity.node_id(),
            done: probe.target == identity.node_id(),
            expires: probe.expires,
            signature: vec![],
        };
        reply.signature = identity.sign(REPLY_DOMAIN, &reply.payload()?).to_vec();
        Ok(reply)
    }
    pub fn verify(&self, now: u64) -> Result<()> {
        ensure!(
            self.ttl > 0
                && self.ttl <= 32
                && self.expires >= now
                && self.expires <= now + 5
                && self.done == (self.node == self.target),
            "trace reply bounds"
        );
        self.node.verify(
            REPLY_DOMAIN,
            &self.payload()?,
            self.signature
                .as_slice()
                .try_into()
                .context("trace signature")?,
        )
    }
}
pub struct Trace {
    pub target: NodeId,
    pub started: Instant,
    pub max_hops: u8,
    pub hops: BTreeMap<u8, Value>,
    pub done: Option<u8>,
    pub reply: oneshot::Sender<Value>,
}
pub struct Ping {
    pub target: NodeId,
    pub started: Instant,
    pub hash: blake3::Hash,
    pub bytes: usize,
    pub reply: oneshot::Sender<Value>,
}
#[derive(Default)]
pub struct Diagnostics {
    pub traces: BTreeMap<u64, Trace>,
    pub pings: BTreeMap<u64, Ping>,
}
impl Diagnostics {
    pub fn forget(&mut self, node: NodeId) {
        let pings: Vec<_> = self
            .pings
            .iter()
            .filter(|(_, p)| p.target == node)
            .map(|(&id, _)| id)
            .collect();
        for id in pings {
            if let Some(ping) = self.pings.remove(&id) {
                let _ = ping
                    .reply
                    .send(json!({"error":"target membership revoked"}));
            }
        }
        let traces: Vec<_> = self
            .traces
            .iter()
            .filter(|(_, t)| t.target == node)
            .map(|(&id, _)| id)
            .collect();
        for id in traces {
            if let Some(trace) = self.traces.remove(&id) {
                let _ = trace
                    .reply
                    .send(json!({"error":"target membership revoked"}));
            }
        }
    }
    pub fn receive_trace(&mut self, reply: Reply, now: Instant) {
        if let Some(trace) = self.traces.get_mut(&reply.id) {
            if trace.target != reply.target || reply.ttl > trace.max_hops {
                return;
            }
            trace.hops.entry(reply.ttl).or_insert_with(|| json!({"ttl":reply.ttl,"node":reply.node,"rtt_ms":now.saturating_duration_since(trace.started).as_secs_f64()*1000.0}));
            if reply.done {
                trace.done = Some(trace.done.map_or(reply.ttl, |old| old.min(reply.ttl)));
            }
        }
    }
    pub fn maintain(&mut self, now: Instant) {
        let completed: Vec<_> = self
            .traces
            .iter()
            .filter(|(_, t)| {
                t.reply.is_closed()
                    || now.saturating_duration_since(t.started) >= Duration::from_secs(3)
                    || t.done
                        .is_some_and(|n| (1..=n).all(|i| t.hops.contains_key(&i)))
            })
            .map(|(&id, _)| id)
            .collect();
        for id in completed {
            let t = self.traces.remove(&id).expect("trace snapshot");
            let max = t.done.unwrap_or(t.max_hops);
            let hops: Vec<_> = (1..=max)
                .map(|i| {
                    t.hops
                        .get(&i)
                        .cloned()
                        .unwrap_or_else(|| json!({"ttl":i,"timeout":true}))
                })
                .collect();
            let _ = t
                .reply
                .send(json!({"target":t.target,"complete":t.done.is_some(),"hops":hops}));
        }
        let expired: Vec<_> = self
            .pings
            .iter()
            .filter(|(_, p)| {
                p.reply.is_closed()
                    || now.saturating_duration_since(p.started) >= Duration::from_secs(4)
            })
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            if let Some(p) = self.pings.remove(&id) {
                let _ = p.reply.send(json!({"error":"overlay ping timed out"}));
            }
        }
    }
}
