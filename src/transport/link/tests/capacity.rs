//! Actual Link/FEC/RTX over a finite serialization queue; not a wall-clock benchmark.
use super::*;
use std::collections::BTreeMap;

#[test]
fn capacity_drop_backs_off_and_restoration_recovers_useful_delivery() {
    let origin = Instant::now();
    let mut links = [link(origin), link(origin)];
    let mut wire = BTreeMap::<u64, Vec<(usize, Vec<u8>)>>::new();
    let mut available_us = [0_u64; 2];
    let mut dropped = [0; 2];
    let mut restored_delivery = 0;
    for ms in 0..31_000 {
        let now = origin + Duration::from_millis(ms);
        if ms < 30_000 {
            for (source, period, size) in [(0, 1, 900), (1, 1000, 1)] {
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
        while wire
            .first_key_value()
            .is_some_and(|(at, _)| *at <= ms * 1000)
        {
            for (dest, bytes) in wire.pop_first().unwrap().1 {
                for message in links[dest].receive_authenticated(&bytes, now).unwrap() {
                    assert_eq!(
                        message.payload,
                        vec![(1 - dest) as u8; if dest == 0 { 1 } else { 900 }]
                    );
                    if dest == 1 && (26_000..30_000).contains(&ms) {
                        restored_delivery += 1;
                    }
                }
            }
        }
        for (source, link) in links.iter_mut().enumerate() {
            for packet in link.poll(now, 64).unwrap() {
                let bps = if source == 0 && (5000..20_000).contains(&ms) {
                    2_000_000
                } else {
                    10_000_000
                };
                let duration_us =
                    ((packet.len() + frame::WIRE_OVERHEAD) as u64 * 8 * 1_000_000).div_ceil(bps);
                if available_us[source] > ms * 1000 + 100_000 {
                    dropped[source] += 1;
                    continue;
                }
                available_us[source] = available_us[source].max(ms * 1000) + duration_us;
                wire.entry(available_us[source] + 10_000)
                    .or_default()
                    .push((1 - source, packet));
            }
        }
        if ms == 10_000 {
            assert!(
                links[0].stats().control.rate_bps < 3_000_000,
                "capacity drop must reduce the estimate"
            );
            assert!(links[0].stats().control.delay_backoffs > 0);
        }
    }
    assert!(
        dropped[0] > 0,
        "the bottleneck must actually drop wire packets"
    );
    assert_eq!(dropped[1], 0);
    assert!(
        restored_delivery >= 3600,
        "restored capacity still starves payload: {restored_delivery}"
    );
    assert!(links[0].stats().control.rate_bps >= 8_000_000);
    assert_eq!(links[0].stats().queued_bytes, 0);
    assert_eq!(links[0].stats().in_flight, 0);
}
