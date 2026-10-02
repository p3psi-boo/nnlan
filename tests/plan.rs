use nnlan::{
    config::{Config, PeerConfig},
    identity::Identity,
    plan::Plan,
    routing::exit::{ExitDecision, ExitPolicy},
};

#[test]
fn selected_exit_is_a_blocked_desired_policy_not_an_installed_guard() {
    let local = Identity::generate().unwrap();
    let remote = Identity::generate().unwrap();
    let mut config = Config::default();
    config.routes.exit_node = Some(remote.node_id());
    let plan = Plan::build(&config, &local).unwrap();
    assert!(!plan.kernel_exit_guard_installed);
    assert!(!plan.network_running);
    assert!(matches!(
        plan.desired_exit_policy,
        ExitPolicy::Selected { .. }
    ));
    assert_eq!(
        plan.desired_exit_policy.decide(false),
        ExitDecision::Blocked
    );
    assert_eq!(plan.desired_exit_policy.decide(true), ExitDecision::Blocked);
}

#[test]
fn self_peering_and_self_exit_are_errors() {
    let local = Identity::generate().unwrap();
    let mut config = Config::default();
    config.routes.exit_node = Some(local.node_id());
    assert!(Plan::build(&config, &local).is_err());
    config.routes.exit_node = None;
    config.peers.push(PeerConfig {
        endpoint: "localhost:7331".into(),
        public_key: local.node_id(),
    });
    assert!(Plan::build(&config, &local).is_err());
}

#[test]
fn forwarding_roles_do_not_create_local_or_exit_loops() {
    use nnlan::config::AcceptedRoute;
    let local = Identity::generate().unwrap();
    let remote = Identity::generate().unwrap();
    let mut config = Config::default();
    config.routes.serve_exit = true;
    assert!(Plan::build(&config, &local).is_ok());
    config.routes.exit_node = Some(remote.node_id());
    assert!(Plan::build(&config, &local).is_err());
    config.routes.serve_exit = false;
    assert!(Plan::build(&config, &local).is_ok());
    config.routes.accept.push(AcceptedRoute {
        prefix: "192.168.77.0/24".parse().unwrap(),
        via: local.node_id(),
    });
    assert!(Plan::build(&config, &local).is_err());
    config.routes.accept[0].via = remote.node_id();
    assert!(Plan::build(&config, &local).is_ok());
}
