//! Local persistent denial overrides every introduction, not a global revocation CA.
use super::*;
use admin::MemberAction;

impl Engine {
    pub(super) fn members_status(&self) -> Value {
        json!({
            "denied": self.config.denied,
            "trusted": self.control.records()
                .filter(|r| self.control.trusted(r.descriptor.node))
                .map(|r| r.descriptor.node).collect::<Vec<_>>(),
        })
    }

    pub(super) fn update_member(&mut self, action: MemberAction, now: Instant) -> Result<Value> {
        let mut desired = self.config.clone();
        let (node, deny) = match action {
            MemberAction::Deny { node } => (node, true),
            MemberAction::Allow { node } => (node, false),
        };
        ensure!(
            node != self.identity.node_id(),
            "cannot change local membership"
        );
        let changed = if deny {
            desired.denied.insert(node)
        } else {
            desired.denied.remove(&node)
        };
        if !changed {
            return Ok(self.members_status());
        }
        // Persistence precedes acknowledgement. No peer, subnet or exit choice
        // is silently removed: an unavailable selected publisher stays blocked.
        desired.save(&self.config_path)?;
        self.config = desired;
        self.transport.set_denied(self.config.denied.clone());
        self.control.set_denied(self.config.denied.clone());
        if deny {
            self.endpoints.disconnected(node);
            self.gossip.remove(&node);
            self.verify_limits.remove(&node);
            self.forget_member(node);
            self.transport.discard_queued();
        }
        let result = (|| {
            self.publish(now)?;
            self.refresh(unix_time()?)?;
            self.connect_at = now - Duration::from_secs(1);
            Ok(self.members_status())
        })();
        if result.is_err() {
            // A kernel/state failure after commit must not leave a half-applied
            // daemon running. Persistent route guards survive process exit.
            self.stopping = true;
        }
        result
    }

    pub(super) fn forget_member(&mut self, node: NodeId) {
        self.direct_attempt.remove(&node);
        self.diagnostics.forget(node);
    }
}
