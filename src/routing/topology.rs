use crate::identity::NodeId;
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque},
};

#[derive(Default)]
struct Node {
    relay: bool,
    neighbors: BTreeMap<NodeId, u32>,
}

pub struct Topology {
    nodes: BTreeMap<NodeId, Node>,
    capacity: usize,
}

/// A control-plane prediction, not the result of an active trace probe.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct RoutePath {
    pub nodes: Vec<NodeId>,
    pub cost: u64,
}

impl Topology {
    pub fn new(capacity: usize) -> Self {
        Self {
            nodes: BTreeMap::new(),
            capacity,
        }
    }

    /// Input must come from current, authenticated node descriptions.
    pub fn set_node(&mut self, id: NodeId, relay: bool) -> Result<()> {
        ensure!(
            self.nodes.contains_key(&id) || self.nodes.len() < self.capacity,
            "topology capacity reached"
        );
        self.nodes.entry(id).or_default().relay = relay;
        Ok(())
    }

    /// Install only mutually confirmed live adjacency; one-sided advertisements
    /// must not manufacture a link. The control layer validates signatures/expiry.
    pub fn set_link(&mut self, a: NodeId, b: NodeId, cost: u32) -> Result<()> {
        ensure!(
            a != b && cost > 0,
            "links need distinct endpoints and positive cost"
        );
        ensure!(
            self.nodes.contains_key(&a) && self.nodes.contains_key(&b),
            "unknown link endpoint"
        );
        self.nodes
            .get_mut(&a)
            .expect("checked endpoint")
            .neighbors
            .insert(b, cost);
        self.nodes
            .get_mut(&b)
            .expect("checked endpoint")
            .neighbors
            .insert(a, cost);
        Ok(())
    }

    pub fn remove_link(&mut self, a: NodeId, b: NodeId) {
        if let Some(node) = self.nodes.get_mut(&a) {
            node.neighbors.remove(&b);
        }
        if let Some(node) = self.nodes.get_mut(&b) {
            node.neighbors.remove(&a);
        }
    }

    pub fn remove_node(&mut self, id: NodeId) {
        self.nodes.remove(&id);
        for node in self.nodes.values_mut() {
            node.neighbors.remove(&id);
        }
    }

    pub fn route(&self, source: NodeId, target: NodeId) -> Option<RoutePath> {
        self.route_where(source, target, |_, _| true)
    }

    /// A deterministic retained graph, computed once per topology update.
    /// Configured edges and non-relay attachments remain; Kruskal's ordered
    /// forest connects relay components without relying on removable shortcuts.
    pub fn retention_plan(&self, protected: &BTreeSet<(NodeId, NodeId)>) -> RetentionPlan {
        let mut graph = Topology::new(self.capacity);
        let mut components: BTreeMap<_, _> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.relay)
            .map(|(&id, _)| (id, id))
            .collect();
        for (&id, node) in &self.nodes {
            graph.set_node(id, node.relay).expect("same capacity");
        }
        for (&a, node) in &self.nodes {
            for (&b, &cost) in node
                .neighbors
                .range((std::ops::Bound::Excluded(a), std::ops::Bound::Unbounded))
            {
                if protected.contains(&(a, b)) || !node.relay || !self.nodes[&b].relay {
                    graph.set_link(a, b, cost).expect("known endpoints");
                    if node.relay && self.nodes[&b].relay {
                        join(&mut components, a, b);
                    }
                }
            }
        }
        // BTreeMap traversal gives a global (min endpoint, max endpoint) order.
        for (&a, node) in &self.nodes {
            if !node.relay {
                continue;
            }
            for (&b, &cost) in node
                .neighbors
                .range((std::ops::Bound::Excluded(a), std::ops::Bound::Unbounded))
            {
                if self.nodes[&b].relay && join(&mut components, a, b) {
                    graph.set_link(a, b, cost).expect("known endpoints");
                }
            }
        }
        let relay_nodes: Vec<_> = components.keys().copied().collect();
        let centers: BTreeSet<_> = relay_nodes
            .into_iter()
            .map(|id| root(&mut components, id))
            .collect();
        let mut safe = BTreeSet::new();
        for center in centers {
            let mut distance = BTreeMap::from([(center, 0_usize)]);
            let mut queue = VecDeque::from([center]);
            while let Some(node) = queue.pop_front() {
                if !graph.nodes[&node].relay {
                    continue;
                }
                let next_distance = distance[&node] + 1;
                for &next in graph.nodes[&node].neighbors.keys() {
                    if let std::collections::btree_map::Entry::Vacant(entry) = distance.entry(next)
                    {
                        entry.insert(next_distance);
                        queue.push_back(next);
                    }
                }
            }
            // A retained relay center within 16 hops gives an actual <=32-hop
            // path between every pair, even AFTER every concurrent retirement.
            // If this sufficient bound fails, keep shortcuts conservatively.
            if distance.values().all(|&hops| hops <= 16) {
                safe.extend(distance.into_keys());
            }
        }
        RetentionPlan { graph, safe }
    }

    fn route_where(
        &self,
        source: NodeId,
        target: NodeId,
        allowed: impl Fn(NodeId, NodeId) -> bool,
    ) -> Option<RoutePath> {
        if !self.nodes.contains_key(&source) || !self.nodes.contains_key(&target) {
            return None;
        }
        let mut distance = BTreeMap::from([(source, 0_u64)]);
        let mut previous = BTreeMap::new();
        let mut queue = BinaryHeap::from([Reverse((0_u64, source))]);
        while let Some(Reverse((cost, id))) = queue.pop() {
            if distance.get(&id) != Some(&cost) {
                continue;
            }
            if id == target {
                let mut nodes = vec![target];
                let mut current = target;
                while current != source {
                    current = *previous.get(&current)?;
                    nodes.push(current);
                }
                nodes.reverse();
                return Some(RoutePath { nodes, cost });
            }
            let node = self.nodes.get(&id)?;
            if id != source && !node.relay {
                continue;
            }
            for (&next, &edge) in &node.neighbors {
                if !allowed(id, next) {
                    continue;
                }
                let proposed = cost.checked_add(u64::from(edge))?;
                if distance.get(&next).is_none_or(|old| proposed < *old) {
                    distance.insert(next, proposed);
                    previous.insert(next, id);
                    queue.push(Reverse((proposed, next)));
                }
            }
        }
        None
    }
}

pub struct RetentionPlan {
    graph: Topology,
    safe: BTreeSet<NodeId>,
}
impl RetentionPlan {
    pub fn path(&self, source: NodeId, target: NodeId) -> Option<RoutePath> {
        if !self.safe.contains(&source)
            || !self.safe.contains(&target)
            || self
                .graph
                .nodes
                .get(&source)?
                .neighbors
                .contains_key(&target)
        {
            return None;
        }
        let path = self.graph.route(source, target)?;
        (path.nodes.len() > 2 && path.nodes.len() <= 33).then_some(path)
    }
}

fn root(components: &mut BTreeMap<NodeId, NodeId>, id: NodeId) -> NodeId {
    let mut top = id;
    while components[&top] != top {
        top = components[&top];
    }
    let mut current = id;
    while current != top {
        let next = components[&current];
        components.insert(current, top);
        current = next;
    }
    top
}
fn join(components: &mut BTreeMap<NodeId, NodeId>, a: NodeId, b: NodeId) -> bool {
    let a = root(components, a);
    let b = root(components, b);
    if a == b {
        return false;
    }
    components.insert(a.max(b), a.min(b));
    true
}

pub fn edge_key(a: NodeId, b: NodeId) -> (NodeId, NodeId) {
    (a.min(b), a.max(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn multihop_direct_upgrade_and_relay_opt_out() {
        let [a, b, c, d] = [1, 2, 3, 4].map(test_id);
        let mut graph = Topology::new(4);
        for id in [a, b, c, d] {
            graph.set_node(id, true).unwrap();
        }
        for (x, y) in [(a, c), (c, d), (d, b)] {
            graph.set_link(x, y, 1).unwrap();
        }
        assert_eq!(graph.route(a, b).unwrap().nodes, [a, c, d, b]);
        graph.set_link(a, b, 1).unwrap();
        assert_eq!(graph.route(a, b).unwrap().nodes, [a, b]);
        graph.remove_link(a, b);
        graph.set_node(d, false).unwrap();
        assert!(graph.route(a, b).is_none());
        assert!(graph.route(a, d).is_some()); // Non-relays remain reachable endpoints.
        graph.remove_node(c);
        assert!(graph.route(a, d).is_none());
    }

    #[test]
    fn bounded_topology_with_cycles() {
        let [a, b, c] = [1, 2, 3].map(test_id);
        let mut g = Topology::new(3);
        for id in [a, b, c] {
            g.set_node(id, true).unwrap();
        }
        assert!(g.set_node(test_id(4), true).is_err());
        g.set_link(a, b, 10).unwrap();
        g.set_link(b, c, 10).unwrap();
        g.set_link(c, a, 1).unwrap();
        assert_eq!(g.route(a, b).unwrap().cost, 10);
        assert_eq!(g.route(a, a).unwrap().nodes, [a]);
        assert!(g.set_link(a, a, 1).is_err());
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn simultaneous_retirements_preserve_every_five_node_graph_component() {
        let ids: Vec<_> = (1..=5).map(test_id).collect();
        let edges: Vec<_> = (0..5)
            .flat_map(|a| (a + 1..5).map(move |b| (a, b)))
            .collect();
        for mask in 0_u16..1 << edges.len() {
            for protect in [false, true] {
                let mut graph = Topology::new(5);
                for &id in &ids {
                    graph.set_node(id, true).unwrap();
                }
                let mut protected = BTreeSet::new();
                for (index, &(a, b)) in edges.iter().enumerate() {
                    if mask & (1 << index) != 0 {
                        graph.set_link(ids[a], ids[b], 1).unwrap();
                        if protect && index % 3 == 0 {
                            protected.insert(edge_key(ids[a], ids[b]));
                        }
                    }
                }
                let before: Vec<_> = edges
                    .iter()
                    .map(|&(a, b)| graph.route(ids[a], ids[b]).is_some())
                    .collect();
                // Every decision uses the old snapshot, before any other peer's
                // withdrawal is observed. Remove the entire chosen set at once.
                let retire: Vec<_> = edges
                    .iter()
                    .filter(|&&(a, b)| {
                        graph.nodes[&ids[a]].neighbors.contains_key(&ids[b])
                            && graph
                                .retention_plan(&protected)
                                .path(ids[a], ids[b])
                                .is_some()
                    })
                    .copied()
                    .collect();
                for (a, b) in retire {
                    assert!(!protected.contains(&edge_key(ids[a], ids[b])));
                    graph.remove_link(ids[a], ids[b]);
                }
                for (index, &(a, b)) in edges.iter().enumerate() {
                    assert_eq!(
                        graph.route(ids[a], ids[b]).is_some(),
                        before[index],
                        "mask={mask} protected={protect}"
                    );
                }
            }
        }
    }

    #[test]
    fn necessary_edges_non_relays_and_hop_limit_block_retirement() {
        let ids: Vec<_> = (1..=35).map(test_id).collect();
        let mut graph = Topology::new(ids.len());
        for &id in &ids {
            graph.set_node(id, true).unwrap();
        }
        let mut protected = BTreeSet::new();
        for pair in ids.windows(2) {
            graph.set_link(pair[0], pair[1], 1).unwrap();
            protected.insert(edge_key(pair[0], pair[1]));
        }
        // Only 34-hop backup exists, beyond the envelope's actual TTL budget.
        graph.set_link(ids[0], ids[34], 1).unwrap();
        assert!(
            graph
                .retention_plan(&protected)
                .path(ids[0], ids[34])
                .is_none()
        );
        graph = Topology::new(3);
        protected.clear();
        for &id in &ids[..3] {
            graph.set_node(id, true).unwrap();
        }
        for pair in ids[..3].windows(2) {
            graph.set_link(pair[0], pair[1], 1).unwrap();
            protected.insert(edge_key(pair[0], pair[1]));
        }
        graph.set_link(ids[0], ids[2], 1).unwrap();
        assert_eq!(
            graph
                .retention_plan(&protected)
                .path(ids[0], ids[2])
                .unwrap()
                .nodes,
            ids[..3]
        );
        graph.set_node(ids[1], false).unwrap();
        assert!(
            graph
                .retention_plan(&protected)
                .path(ids[0], ids[2])
                .is_none()
        );
        graph.remove_link(ids[1], ids[2]);
        assert!(
            graph
                .retention_plan(&protected)
                .path(ids[0], ids[2])
                .is_none()
        );
    }
}

#[cfg(test)]
mod hop_budget_tests {
    use super::*;
    use crate::identity::test_id;

    #[test]
    fn individually_short_backups_do_not_justify_a_final_over_budget_network() {
        let mut ids: Vec<_> = (1..=40).map(test_id).collect();
        ids.sort();
        let mut graph = Topology::new(ids.len());
        let mut protected = BTreeSet::new();
        for &id in &ids {
            graph.set_node(id, true).unwrap();
        }
        for pair in ids.windows(2) {
            graph.set_link(pair[0], pair[1], 1).unwrap();
            protected.insert(edge_key(pair[0], pair[1]));
        }
        // Each shortcut separately has a protected 20-hop backup. Removing
        // BOTH is graph-connected but changes this reachable 3-hop route to 39.
        graph.set_link(ids[0], ids[20], 1).unwrap();
        graph.set_link(ids[19], ids[39], 1).unwrap();
        assert_eq!(graph.route(ids[0], ids[39]).unwrap().nodes.len(), 4);
        let plan = graph.retention_plan(&protected);
        assert!(plan.path(ids[0], ids[20]).is_none());
        assert!(plan.path(ids[19], ids[39]).is_none());
    }
}
