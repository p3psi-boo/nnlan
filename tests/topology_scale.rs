//! Algorithmic scale check, not a network throughput or thousand-daemon benchmark.
use nnlan::{identity::Identity, routing::topology::Topology};

#[test]
fn thousand_node_sparse_ring_is_reachable_without_full_mesh() {
    let ids: Vec<_> = (0..1000)
        .map(|_| Identity::generate().unwrap().node_id())
        .collect();
    let mut graph = Topology::new(ids.len());
    for &id in &ids {
        graph.set_node(id, true).unwrap();
    }
    for i in 0..ids.len() {
        graph.set_link(ids[i], ids[(i + 1) % ids.len()], 1).unwrap();
    }
    let path = graph.route(ids[0], ids[500]).unwrap();
    assert_eq!(path.cost, 500);
    assert_eq!(path.nodes.len(), 501);
    // Two neighbors per node, even though every node is reachable.
    graph.remove_node(ids[250]);
    assert!(graph.route(ids[0], ids[500]).is_some());
}
