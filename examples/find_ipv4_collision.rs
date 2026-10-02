//! Reproduce the public test-only collision fixture, not deployment identities.
use nnlan::{address::candidate, identity::NodeId};
use std::collections::HashMap;
fn main() {
    let mut seen = HashMap::new();
    for i in 0_u64..100_000 {
        let seed = *blake3::hash(&i.to_be_bytes()).as_bytes();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let node = NodeId::from_bytes(key.verifying_key().to_bytes()).unwrap();
        let ip = candidate(node, 0).ipv4;
        if let Some((previous, previous_seed)) = seen.insert(ip, (i, seed)) {
            let hex = |s: [u8; 32]| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
            println!(
                "{}",
                serde_json::json!({"counter_a":previous,"counter_b":i,"seed_a":hex(previous_seed),"seed_b":hex(seed),"ipv4":ip.to_string()})
            );
            return;
        }
    }
    panic!("no collision in search budget");
}
