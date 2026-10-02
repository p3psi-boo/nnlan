//! Exercise the actual FEC, RTX and feedback queues, not an unlimited ACK model.
use super::*;
use std::collections::BTreeMap;

#[test]
fn overload_keeps_delivering_payload_instead_of_only_expired_group_seals() {
    let origin = Instant::now();
    let mut links = [
        Link::new(link(origin).scope(), 64_000, origin, Default::default()).unwrap(),
        link(origin),
    ];
    let mut wire = BTreeMap::<u64, Vec<(usize, Vec<u8>)>>::new();
    let mut received = 0;
    let mut late_received = 0;
    // Deliberately offer much more than the configured wire limit. Losing old
    // payload is expected; spending the entire limit on orphan seals is not.
    for ms in 0..12_000 {
        let now = origin + Duration::from_millis(ms);
        if ms < 10_000 {
            links[0]
                .enqueue(
                    Message {
                        kind: 1,
                        payload: vec![7; 900],
                    },
                    now,
                )
                .unwrap();
        }
        while wire.first_key_value().is_some_and(|(at, _)| *at <= ms) {
            for (dest, bytes) in wire.pop_first().unwrap().1 {
                for message in links[dest].receive_authenticated(&bytes, now).unwrap() {
                    assert_eq!(dest, 1);
                    assert_eq!(message.payload, vec![7; 900]);
                    received += 1;
                    if ms >= 5000 {
                        late_received += 1;
                    }
                }
            }
        }
        for (source, link) in links.iter_mut().enumerate() {
            for bytes in link.poll(now, 64).unwrap() {
                wire.entry(ms + 1).or_default().push((1 - source, bytes));
            }
        }
    }
    let stats = links[0].stats();
    assert!(
        received >= 40,
        "less than half the available wire budget delivered payload: {received}"
    );
    assert!(
        late_received >= 20,
        "ongoing overload starved all late payload: {late_received}"
    );
    assert!(stats.tx_wire_bytes <= 2400 + 12 * 8000);
    assert!(stats.queue_dropped > 0);
    assert!(stats.unsent_sources_dropped > 0);
    assert_eq!(stats.queued_bytes, 0);
    assert_eq!(stats.in_flight, 0);
}

#[test]
fn sparse_reverse_traffic_does_not_starve_forward_acknowledgments() {
    let origin = Instant::now();
    let mut links = [link(origin), link(origin)];
    let mut wire = BTreeMap::<u64, Vec<(usize, Vec<u8>)>>::new();
    let mut random = 1_u64;
    let mut received = [0; 2];
    // A sends 900 bytes every 5 ms; B sends a one-byte heartbeat each second.
    // Both directions have independent 1..101 ms delay, but no packet loss.
    // Stop producing for the last second so all queued deliveries can drain.
    for ms in 0..121_000 {
        let now = origin + Duration::from_millis(ms);
        if ms < 120_000 {
            for (source, period, size) in [(0, 5, 900), (1, 1000, 1)] {
                if ms % period == 0 {
                    links[source]
                        .enqueue(
                            Message {
                                kind: 1,
                                payload: vec![source as u8; size],
                            },
                            now,
                        )
                        .unwrap();
                }
            }
        }
        while wire.first_key_value().is_some_and(|(at, _)| *at <= ms) {
            for (dest, bytes) in wire.pop_first().unwrap().1 {
                for message in links[dest].receive_authenticated(&bytes, now).unwrap() {
                    assert_eq!(message.kind, 1);
                    assert_eq!(
                        message.payload,
                        vec![(1 - dest) as u8; if dest == 0 { 1 } else { 900 }]
                    );
                    received[dest] += 1;
                }
            }
        }
        for (source, link) in links.iter_mut().enumerate() {
            for bytes in link.poll(now, 64).unwrap() {
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                wire.entry(ms + 1 + (random >> 32) % 101)
                    .or_default()
                    .push((1 - source, bytes));
            }
        }
    }
    assert_eq!(received, [120, 24_000], "lossless delivery including drain");
    let reverse = links[1].stats();
    assert_eq!(
        reverse.control.delay_backoffs, 0,
        "heartbeats are not a delay trend"
    );
    assert_eq!(
        reverse.control.stale_backoffs, 0,
        "ACKs do not require ACKs"
    );
    assert_eq!(reverse.queue_dropped, 0);
    assert!(links[0].stats().fec_sent > 0 && reverse.fec_sent > 0);
}

#[test]
fn high_rate_one_way_data_has_bounded_timely_feedback_without_reverse_sources() {
    let origin = Instant::now();
    let mut links = [
        Link::new(
            link(origin).scope(),
            1_000_000_000,
            origin,
            Default::default(),
        )
        .unwrap(),
        Link::new(
            link(origin).scope(),
            1_000_000_000,
            origin,
            Default::default(),
        )
        .unwrap(),
    ];
    let mut wire = BTreeMap::<u64, Vec<(usize, Vec<u8>)>>::new();
    let mut offered = 0;
    let mut rejected = 0;
    let mut delivered = 0;
    // Crossed key epochs put application sources on different Links. Model one
    // such pair: the receiver sends ACK/NACK only, never application sources
    // whose acknowledgments could increase its outgoing bandwidth estimate.
    for ms in 0..17_000 {
        let now = origin + Duration::from_millis(ms);
        let count = if ms < 15_000 {
            1
        } else if ms < 16_000 {
            16
        } else {
            0
        };
        for _ in 0..count {
            offered += 1;
            rejected += usize::from(
                links[0]
                    .enqueue(
                        Message {
                            kind: 1,
                            payload: vec![7; 900],
                        },
                        now,
                    )
                    .is_err(),
            );
        }
        while wire.first_key_value().is_some_and(|(at, _)| *at <= ms) {
            for (dest, bytes) in wire.pop_first().unwrap().1 {
                for message in links[dest].receive_authenticated(&bytes, now).unwrap() {
                    assert_eq!(dest, 1);
                    assert_eq!(message.payload, vec![7; 900]);
                    delivered += 1;
                }
            }
        }
        for (source, link) in links.iter_mut().enumerate() {
            for bytes in link.poll(now, 64).unwrap() {
                wire.entry(ms + 1).or_default().push((1 - source, bytes));
            }
        }
    }
    let forward = links[0].stats();
    let reverse = links[1].stats();
    eprintln!(
        "offered={offered} rejected={rejected} delivered={delivered} expired={} reverse_drop={} reverse_wire={} reverse_rate={}",
        forward.expired_sources,
        reverse.queue_dropped,
        reverse.tx_wire_bytes,
        reverse.control.rate_bps
    );
    assert_eq!(
        rejected, 0,
        "timely ACKs must release source-cache capacity"
    );
    assert_eq!(delivered, offered);
    assert_eq!(forward.expired_sources, 0);
    assert_eq!(reverse.original_sent, 0);
    assert_eq!(reverse.queue_dropped, 0);
    assert_eq!(forward.in_flight, 0);
    assert_eq!(reverse.queued_bytes, 0);
    // Feedback is not exempt from the total pacer or instance bandwidth limit.
    assert!(reverse.tx_wire_bytes <= 2400 + 17 * 8_100_000 / 8);
}
