//! Explicit local route intent, separate from membership and signed advertisements.
use super::*;
use crate::config::{AcceptedRoute, validate_subnet};

impl Engine {
    pub(super) fn routes_status(&mut self) -> Value {
        let selected: Vec<_> = self.config.routes.accept.clone().into_iter().map(|r| {
            let available = self.control.trusted(r.via)
                && self.control.record(r.via).is_some_and(|record| record.descriptor.subnets.contains(&r.prefix))
                && self.control.path(r.via).is_some();
            json!({"prefix":r.prefix,"via":r.via,"state":if available {"forward"} else {"blocked"}})
        }).collect();
        json!({
            "advertised":self.control.records().filter(|r| self.control.trusted(r.descriptor.node))
                .map(|r| json!({"via":r.descriptor.node,"prefixes":r.descriptor.subnets,"serve_exit":r.descriptor.serve_exit})).collect::<Vec<_>>(),
            "accepted":self.config.routes.accept,
            "selected":selected,
            "exit_node":self.config.routes.exit_node,
            "exit_state": if self.config.routes.exit_node.is_none() { "disabled" } else if self.exit_available() { "active" } else { "unreachable" },
            "serve_exit":self.config.routes.serve_exit,
            "kernel_subnet_policy_installed":self.kernel.is_some()
        })
    }

    fn selected_subnet(&self, address: IpAddr) -> Option<&AcceptedRoute> {
        self.config
            .routes
            .accept
            .iter()
            .filter(|r| r.prefix.contains(&address))
            .max_by_key(|r| r.prefix.prefix_len())
    }
    fn subnet_peer(&mut self, address: IpAddr) -> Result<Option<NodeId>> {
        let Some(route) = self.selected_subnet(address) else {
            return Ok(None);
        };
        let (prefix, via) = (route.prefix, route.via);
        ensure!(
            self.control.trusted(via)
                && self
                    .control
                    .record(via)
                    .is_some_and(|r| r.descriptor.subnets.contains(&prefix)),
            "selected subnet publisher has withdrawn or expired"
        );
        ensure!(
            self.control.path(via).is_some(),
            "selected subnet publisher is unreachable"
        );
        Ok(Some(via))
    }
    pub(super) fn outbound_ip_peer(
        &mut self,
        source: IpAddr,
        destination: IpAddr,
    ) -> Result<NodeId> {
        let local = self.identity.node_id();
        let source_owner = self.control.node_for_ip(source);
        if let Some(peer) = self.control.node_for_ip(destination) {
            ensure!(
                source_owner == Some(local)
                    || (!overlay_address(source)
                        && (self.config.routes.serve_exit
                            || self
                                .config
                                .routes
                                .advertise
                                .iter()
                                .any(|p| p.contains(&source)))),
                "local IP source binding"
            );
            return Ok(peer);
        }
        ensure!(
            source_owner == Some(local) && !overlay_address(destination),
            "local IP source/destination binding"
        );
        ensure!(routable(destination), "non-unicast exit destination");
        if let Some(peer) = self.subnet_peer(destination)? {
            return Ok(peer);
        }
        self.exit_peer()
            .context("no available selected exit for destination")
    }
    pub(super) fn validate_received_ip(
        &mut self,
        peer: NodeId,
        source: IpAddr,
        destination: IpAddr,
    ) -> Result<()> {
        let local = self.identity.node_id();
        let source_owner = self.control.node_for_ip(source);
        let destination_owner = self.control.node_for_ip(destination);
        let allowed = if destination_owner == Some(local) {
            source_owner == Some(peer)
                || (!overlay_address(source)
                    && if let Some(via) = self.subnet_peer(source)? {
                        via == peer
                    } else {
                        self.exit_peer() == Some(peer)
                    })
        } else {
            source_owner == Some(peer)
                && !overlay_address(destination)
                && routable(destination)
                && (self.config.routes.serve_exit
                    || self
                        .config
                        .routes
                        .advertise
                        .iter()
                        .any(|p| p.contains(&destination)))
        };
        ensure!(allowed, "IP source/destination publisher binding");
        Ok(())
    }
    pub(super) fn update_route(
        &mut self,
        action: admin::RouteAction,
        now: Instant,
    ) -> Result<Value> {
        use admin::RouteAction;
        ensure!(self.tunnel.is_some(), "route changes require a running TUN");
        let mut desired = self.config.clone();
        match action {
            RouteAction::Advertise { prefix } => {
                validate_subnet(prefix)?;
                if !desired.routes.advertise.contains(&prefix) {
                    desired.routes.advertise.push(prefix);
                }
            }
            RouteAction::Withdraw { prefix } => {
                desired.routes.advertise.retain(|p| *p != prefix);
            }
            RouteAction::Accept {
                prefix,
                via,
                replace,
            } => {
                validate_subnet(prefix)?;
                let via = self.control.resolve(&via)?;
                ensure!(
                    via != self.identity.node_id(),
                    "select a remote subnet publisher"
                );
                ensure!(
                    self.control
                        .record(via)
                        .is_some_and(|r| r.descriptor.subnets.contains(&prefix)),
                    "publisher has not advertised this prefix"
                );
                if let Some(route) = desired
                    .routes
                    .accept
                    .iter_mut()
                    .find(|r| r.prefix == prefix)
                {
                    ensure!(
                        replace || route.via == via,
                        "prefix already accepted from another publisher; use --replace"
                    );
                    route.via = via;
                } else {
                    desired.routes.accept.push(AcceptedRoute { prefix, via });
                }
            }
            RouteAction::Reject { prefix } => {
                desired.routes.accept.retain(|r| r.prefix != prefix);
            }
        }
        self.commit_routes(desired, now)
    }
    fn exit_available(&mut self) -> bool {
        self.exit_peer().is_some()
    }
    fn exit_peer(&mut self) -> Option<NodeId> {
        let node = self.config.routes.exit_node?;
        (self.control.trusted(node)
            && self
                .control
                .record(node)
                .is_some_and(|r| r.descriptor.serve_exit)
            && self.control.path(node).is_some())
        .then_some(node)
    }
    pub(super) fn update_exit(&mut self, action: admin::ExitAction, now: Instant) -> Result<Value> {
        ensure!(
            self.tunnel.is_some(),
            "Exit Node changes require a running TUN"
        );
        let mut desired = self.config.clone();
        match action {
            admin::ExitAction::Use { target } => {
                let node = self.control.resolve(&target)?;
                ensure!(
                    node != self.identity.node_id()
                        && self
                            .control
                            .record(node)
                            .is_some_and(|r| r.descriptor.serve_exit),
                    "target has not advertised Exit Node service"
                );
                desired.routes.exit_node = Some(node);
            }
            admin::ExitAction::Off => desired.routes.exit_node = None,
            admin::ExitAction::Serve { enabled } => desired.routes.serve_exit = enabled,
        }
        self.commit_routes(desired, now)
    }
    fn commit_routes(&mut self, desired: Config, now: Instant) -> Result<Value> {
        Plan::build(&desired, &self.identity)?;
        kernel::Policy::preflight(&desired.routes)?;
        let new_dns = if desired.routes.serve_exit && self.dns.is_none() {
            Some(dns::Forwarder::start(
                resolver::servers(&desired, false)?,
                &desired.tun.name,
            )?)
        } else {
            None
        };
        let result = (|| -> Result<()> {
            // Enabling/switching exit: protection precedes the durable selection.
            // Explicit off: persist first, so a crash can only keep blocking.
            if desired.routes.exit_node.is_some() {
                self.kernel
                    .as_mut()
                    .context("kernel policy missing")?
                    .protect(&desired.routes)?;
            }
            desired.save(&self.config_path)?;
            self.config = desired;
            if !self.config.routes.serve_exit {
                self.dns = None;
            } else if new_dns.is_some() {
                self.dns = new_dns;
            }
            self.kernel
                .as_mut()
                .context("kernel policy missing")?
                .apply(
                    &self.config.routes,
                    candidate(self.identity.node_id(), self.state.probe()),
                )?;
            self.publish(now)?;
            self.refresh(unix_time()?)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.stopping = true;
            return Err(error
                .context("route policy update failed; protection retained and daemon stopping"));
        }
        Ok(
            json!({"saved":true,"advertise":self.config.routes.advertise,"accepted":self.config.routes.accept,"exit_node":self.config.routes.exit_node,"serve_exit":self.config.routes.serve_exit}),
        )
    }
}
fn overlay_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => a.octets()[0] == 33,
        IpAddr::V6(a) => a.segments()[0] == 0xfd33,
    }
}

fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !a.is_unspecified()
                && !a.is_loopback()
                && !a.is_multicast()
                && a != std::net::Ipv4Addr::BROADCAST
        }
        IpAddr::V6(a) => !a.is_unspecified() && !a.is_loopback() && !a.is_multicast(),
    }
}

/// Offline cleanup is explicit and must run in the daemon's network namespace.
/// The identity lock and existing nft owner marker prevent touching another instance.
pub(super) fn exit_off(config_path: &Path) -> Result<Value> {
    let mut config = Config::load(config_path)?;
    let identity = Identity::load(&config.identity_path(config_path))?;
    let _state = State::open(&config, config_path, identity.node_id())?;
    let mut policy = kernel::Policy::open(
        identity.node_id(),
        &config.tun.name,
        config.listen.port(),
        config.dhcp_client_uid,
        false,
    )?;
    config.routes.exit_node = None;
    config.save(config_path)?;
    policy.offline(&config.routes)?;
    Ok(json!({"saved":true,"exit_node":null,"offline":true,"kernel_exit_guard_installed":false}))
}
