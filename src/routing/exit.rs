//! Desired policy only: this is NOT a kernel kill switch.
use crate::identity::NodeId;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Reachability {
    pub ipv4: bool,
    pub ipv6: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ExitPolicy {
    #[default]
    Disabled,
    Selected {
        node: NodeId,
        reachable: Reachability,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitDecision {
    Local,
    ForwardVia(NodeId),
    Blocked,
}

impl ExitPolicy {
    pub fn select(&mut self, node: NodeId) {
        *self = Self::Selected {
            node,
            reachable: Reachability::default(),
        };
    }

    pub fn update_reachability(&mut self, observed_node: NodeId, observed: Reachability) {
        if let Self::Selected { node, reachable } = self
            && *node == observed_node
        {
            *reachable = observed;
        }
    }

    pub fn disable_explicitly(&mut self) {
        *self = Self::Disabled;
    }

    pub fn decide(&self, ipv6: bool) -> ExitDecision {
        match self {
            Self::Disabled => ExitDecision::Local,
            Self::Selected { node, reachable } => {
                let available = if ipv6 { reachable.ipv6 } else { reachable.ipv4 };
                if available {
                    ExitDecision::ForwardVia(*node)
                } else {
                    ExitDecision::Blocked
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn only_explicit_disable_restores_local_egress() {
        let mut exit = ExitPolicy::default();
        exit.select(test_id(1));
        assert_eq!(exit.decide(false), ExitDecision::Blocked);
        exit.update_reachability(
            test_id(1),
            Reachability {
                ipv4: true,
                ipv6: false,
            },
        );
        assert_eq!(exit.decide(false), ExitDecision::ForwardVia(test_id(1)));
        assert_eq!(exit.decide(true), ExitDecision::Blocked);
        exit.update_reachability(test_id(1), Reachability::default());
        assert_eq!(exit.decide(false), ExitDecision::Blocked);
        exit.select(test_id(2));
        exit.update_reachability(
            test_id(1),
            Reachability {
                ipv4: true,
                ipv6: true,
            },
        );
        assert_eq!(exit.decide(false), ExitDecision::Blocked);
        exit.disable_explicitly();
        assert_eq!(exit.decide(false), ExitDecision::Local);
    }
}
