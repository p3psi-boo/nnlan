//! Single-epoch test owner. Production UDP owns the controller in Peer instead.
use super::super::*;
use std::ops::{Deref, DerefMut};

pub(super) struct ModelLink {
    epoch: Link,
    pub controller: Controller,
}
impl ModelLink {
    pub fn new(scope: FecScope, max_bps: u64, now: Instant, repair: RepairConfig) -> Result<Self> {
        anyhow::ensure!(max_bps >= 64_000, "link bandwidth below minimum 64 kbps");
        Ok(Self {
            epoch: Link::new(scope, now, repair),
            controller: Controller::new(max_bps, now),
        })
    }
    pub fn set_datagram_limit(&mut self, limit: usize, now: Instant) -> Result<()> {
        self.epoch.set_datagram_limit(limit, now, &self.controller)
    }
    pub fn enqueue(&mut self, message: Message, now: Instant) -> Result<()> {
        self.epoch.enqueue(message, now, &self.controller)
    }
    pub fn receive_authenticated(&mut self, bytes: &[u8], now: Instant) -> Result<Vec<Message>> {
        self.epoch
            .receive_authenticated(bytes, now, &mut self.controller)
    }
    pub fn poll(&mut self, now: Instant, count: usize) -> Result<Vec<Vec<u8>>> {
        if self.epoch.maintained_at != Some(now) {
            let (bytes, pending) = self.epoch.load();
            self.controller.tick(now, bytes, pending);
        }
        self.epoch.poll(now, count, &mut self.controller)
    }
    pub fn stats(&self) -> LinkStats {
        self.epoch.stats(&self.controller)
    }
}
impl Deref for ModelLink {
    type Target = Link;
    fn deref(&self) -> &Link {
        &self.epoch
    }
}
impl DerefMut for ModelLink {
    fn deref_mut(&mut self) -> &mut Link {
        &mut self.epoch
    }
}
