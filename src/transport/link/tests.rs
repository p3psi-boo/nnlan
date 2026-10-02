use super::*;
use crate::identity::test_id;

mod model;
use model::ModelLink as Link;

mod asymmetric;
mod capacity;

fn link(now: Instant) -> Link {
    Link::new(
        FecScope {
            peer: test_id(1),
            path_epoch: 1,
            key_epoch: 1,
            direction: 0,
        },
        10_000_000,
        now,
        Default::default(),
    )
    .unwrap()
}

#[test]
fn feedback_bursts_do_not_starve_reverse_payload() {
    for limit in [frame::MIN_UDP, crate::transport::wire::MAX_UDP] {
        for batch in [1, 64] {
            feedback_burst(limit, batch);
        }
    }
}

fn feedback_burst(limit: usize, batch: usize) {
    let origin = Instant::now();
    let mut a = link(origin);
    let mut b = link(origin);
    a.set_datagram_limit(limit, origin).unwrap();
    b.set_datagram_limit(limit, origin).unwrap();
    let message = Message {
        kind: 1,
        payload: vec![7; 8192],
    };
    a.enqueue(message.clone(), origin).unwrap();
    let mut delivered = Vec::new();
    let mut feedback_packets = 0;
    let mut wire_bytes = 0;
    // A busy receive direction generates ACK batches. A sparse reverse sender
    // still has its initial 2400-byte burst. Scheduling every 20 ms refills both
    // buckets, but strict ACK priority can spend that entire burst every time.
    // No packet loss, deadline extension, unpaced feedback, or extra bandwidth.
    for tick in 1..=20 {
        let now = origin + Duration::from_millis(tick * 20);
        for _ in 0..3 {
            assert!(a.sender.control(
                Frame::Ack(vec![
                    Ack {
                        sequence: u64::MAX,
                        sent_us: 0,
                        received_us: 0,
                        arrival: Arrival::Original,
                    };
                    frame::MAX_FEEDBACK
                ]),
                now
            ));
        }
        for _ in 0..64 / batch {
            let packets = a.poll(now, batch).unwrap();
            if packets.is_empty() {
                break;
            }
            for packet in packets {
                assert!(packet.len() + frame::DATAGRAM_OVERHEAD <= limit);
                wire_bytes += packet.len() + WIRE_OVERHEAD;
                feedback_packets +=
                    usize::from(matches!(Frame::decode(&packet).unwrap(), Frame::Ack(_)));
                delivered.extend(b.receive_authenticated(&packet, now).unwrap());
            }
        }
        for packet in b.poll(now, 64).unwrap() {
            a.receive_authenticated(&packet, now).unwrap();
        }
        if tick == 12 {
            assert_eq!(
                delivered,
                std::slice::from_ref(&message),
                "reverse data must beat its 250 ms queue deadline"
            );
        }
    }
    assert_eq!(delivered, [message]);
    assert_eq!(a.stats().unsent_sources_dropped, 0);
    assert!(feedback_packets >= 20, "feedback must also make progress");
    assert!(wire_bytes <= 2400 + 10_000_000 / 8 * 400 / 1000);
}

#[test]
fn fair_one_packet_rounds_match_batched_polling_and_keep_expiry() {
    let origin = Instant::now();
    let mut batched = link(origin);
    let mut rounds = link(origin);
    let mut emitted = 0;
    for ms in 0..2000 {
        let now = origin + Duration::from_millis(ms);
        if ms < 500 && ms % 3 == 0 {
            let message = Message {
                kind: 1,
                payload: vec![7; 8192],
            };
            batched.enqueue(message.clone(), now).unwrap();
            rounds.enqueue(message, now).unwrap();
        }
        let expected = batched.poll(now, 64).unwrap();
        let mut actual = Vec::new();
        for _ in 0..64 {
            let packet = rounds.poll(now, 1).unwrap();
            if packet.is_empty() {
                break;
            }
            actual.extend(packet);
        }
        emitted += actual.len();
        assert_eq!(actual, expected, "pacing round at {ms} ms");
    }
    assert!(emitted > 100);
    for link in [&batched, &rounds] {
        assert!(link.stats().queue_dropped > 0);
        assert_eq!(link.stats().queued_bytes, 0);
        assert_eq!(link.stats().in_flight, 0);
    }
}

#[test]
fn revocation_discards_queued_fec_and_rtx_without_reusing_frame_identifiers() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    a.enqueue(
        Message {
            kind: 2,
            payload: vec![7; 8192],
        },
        now,
    )
    .unwrap();
    let first = a.poll(now, 1).unwrap().pop().unwrap();
    let Frame::Source { shard, .. } = Frame::decode(&first).unwrap() else {
        panic!("source")
    };
    let old = Fragment::decode(&shard).unwrap();
    let (sequence, message) = (old.sequence, old.message);
    assert!(b.receive_authenticated(&first, now).unwrap().is_empty());
    a.discard_queued();
    assert_eq!(a.stats().queued_bytes, 0);
    assert_eq!(a.stats().in_flight, 0);
    assert!(a.stats().queue_dropped > 0);
    let next = Message {
        kind: 2,
        payload: vec![8; 4096],
    };
    a.enqueue(next.clone(), now).unwrap();
    let mut received = vec![];
    for millis in 0..150 {
        let at = now + Duration::from_millis(millis);
        for bytes in a.poll(at, 64).unwrap() {
            if let Frame::Source { shard, .. } = Frame::decode(&bytes).unwrap() {
                let new = Fragment::decode(&shard).unwrap();
                assert!(new.sequence > sequence && new.message > message);
            }
            received.extend(b.receive_authenticated(&bytes, at).unwrap());
        }
        for bytes in b.poll(at, 64).unwrap() {
            a.receive_authenticated(&bytes, at).unwrap();
        }
    }
    assert_eq!(received, [next]);
}

#[test]
fn originals_are_not_held_for_group_timer() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    let message = Message {
        kind: 1,
        payload: b"immediate".to_vec(),
    };
    a.enqueue(message.clone(), now).unwrap();
    let packets = a.poll(now, 64).unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(
        b.receive_authenticated(&packets[0], now).unwrap(),
        [message]
    );
    assert_eq!(a.stats().fec_sent, 0);
    assert!(
        !a.poll(now + Duration::from_millis(2), 64)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn actual_rs_recovers_two_losses_and_reordered_fragments_without_rtx() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    let message = Message {
        kind: 7,
        payload: (0..frame::FRAGMENT_BYTES * 8)
            .map(|i| (i % 251) as u8)
            .collect(),
    };
    a.enqueue(message.clone(), now).unwrap();
    let mut received = vec![];
    for millis in 0..40 {
        let t = now + Duration::from_millis(millis);
        let mut packets = a.poll(t, 64).unwrap();
        packets.reverse();
        for p in packets {
            if matches!(
                Frame::decode(&p).unwrap(),
                Frame::Source {
                    index: 1 | 4,
                    retransmitted: false,
                    ..
                }
            ) {
                continue;
            }
            received.extend(b.receive_authenticated(&p, t).unwrap());
        }
        for p in b.poll(t, 64).unwrap() {
            a.receive_authenticated(&p, t).unwrap();
        }
    }
    assert_eq!(received, [message]);
    assert_eq!(b.stats().fec_recovered, 2);
    assert_eq!(a.stats().peer_fec_recovered, 2);
    assert_eq!(a.stats().retransmitted, 0);
    assert_eq!(a.stats().in_flight, 0);
}

#[test]
fn bounded_retransmission_recovers_when_parity_is_lost() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    let message = Message {
        kind: 2,
        payload: vec![42; frame::MAX_MESSAGE],
    };
    a.enqueue(message.clone(), now).unwrap();
    let mut received = vec![];
    for millis in 0..700 {
        let t = now + Duration::from_millis(millis);
        for p in a.poll(t, 64).unwrap() {
            if matches!(
                Frame::decode(&p).unwrap(),
                Frame::Source {
                    index: 0,
                    retransmitted: false,
                    ..
                } | Frame::Parity { .. }
            ) {
                continue;
            }
            received.extend(b.receive_authenticated(&p, t).unwrap());
        }
        for p in b.poll(t, 64).unwrap() {
            a.receive_authenticated(&p, t).unwrap();
        }
    }
    assert_eq!(received, [message]);
    assert!(
        a.stats().retransmitted as usize
            >= frame::MAX_MESSAGE
                .div_ceil(frame::FRAGMENT_BYTES)
                .div_ceil(frame::MAX_K)
    );
    assert_eq!(a.stats().expired_sources, 0);
    assert_eq!(a.stats().in_flight, 0);
}

#[test]
fn blackhole_has_finite_retries_and_reclaims_every_source() {
    let now = Instant::now();
    let mut a = link(now);
    a.enqueue(
        Message {
            kind: 1,
            payload: vec![7; 512],
        },
        now,
    )
    .unwrap();
    for millis in 0..1500 {
        a.poll(now + Duration::from_millis(millis), 64).unwrap();
    }
    assert_eq!(a.stats().original_sent, 1);
    assert!(a.stats().retransmitted <= 2);
    assert_eq!(a.stats().expired_sources, 1);
    assert_eq!(a.stats().in_flight, 0);
    assert_eq!(a.stats().queued_bytes, 0);
}

#[test]
fn duplicates_never_deliver_twice_and_queue_admission_is_bounded() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    a.enqueue(
        Message {
            kind: 1,
            payload: vec![7; 512],
        },
        now,
    )
    .unwrap();
    let p = a.poll(now, 64).unwrap().remove(0);
    assert_eq!(b.receive_authenticated(&p, now).unwrap().len(), 1);
    assert!(b.receive_authenticated(&p, now).unwrap().is_empty());
    let message = Message {
        kind: 1,
        payload: vec![1; frame::MAX_MESSAGE],
    };
    let mut accepted = 0;
    while a.enqueue(message.clone(), now).is_ok() {
        accepted += 1;
        assert!(accepted < 100);
    }
    assert!(accepted > 0);
    assert!(a.stats().in_flight <= send::MAX_QUEUE);
}

#[test]
fn pacing_limits_total_wire_bytes_not_just_payload() {
    let now = Instant::now();
    let mut a = Link::new(
        FecScope {
            peer: test_id(1),
            path_epoch: 1,
            key_epoch: 1,
            direction: 0,
        },
        64_000,
        now,
        Default::default(),
    )
    .unwrap();
    a.enqueue(
        Message {
            kind: 1,
            payload: vec![7; 16_000],
        },
        now,
    )
    .unwrap();
    for millis in 0..100 {
        a.poll(now + Duration::from_millis(millis), 64).unwrap();
    }
    assert!(a.stats().tx_wire_bytes <= 2400 + 800);
    assert!(a.stats().queue_dropped > 0 || a.stats().queued_bytes > 0);
}

#[test]
fn small_mtu_fragmentation_feedback_and_fec_survive_reordering() {
    for limit in [frame::MIN_UDP, 620, 900, crate::transport::wire::MAX_UDP] {
        let now = Instant::now();
        let mut a = link(now);
        let mut b = link(now);
        a.set_datagram_limit(limit, now).unwrap();
        // The reverse path has a different PMTU, including ACK aggregation.
        b.set_datagram_limit(frame::MIN_UDP, now).unwrap();
        let message = Message {
            kind: 8,
            payload: (0..frame::MAX_MESSAGE).map(|n| (n % 251) as u8).collect(),
        };
        a.enqueue(message.clone(), now).unwrap();
        let mut received = vec![];
        for ms in 0..900 {
            let t = now + Duration::from_millis(ms);
            let mut packets = a.poll(t, 64).unwrap();
            packets.reverse();
            for packet in packets {
                assert!(packet.len() + frame::DATAGRAM_OVERHEAD <= limit);
                if matches!(
                    Frame::decode(&packet).unwrap(),
                    Frame::Source {
                        index: 1,
                        retransmitted: false,
                        ..
                    }
                ) {
                    continue;
                }
                received.extend(b.receive_authenticated(&packet, t).unwrap());
            }
            for packet in b.poll(t, 64).unwrap() {
                assert!(packet.len() + frame::DATAGRAM_OVERHEAD <= frame::MIN_UDP);
                a.receive_authenticated(&packet, t).unwrap();
            }
        }
        assert_eq!(received, [message]);
        assert!(b.stats().fec_recovered > 0);
        assert_eq!(a.stats().in_flight, 0);
    }
}

#[test]
fn mtu_changes_seal_groups_and_drop_oversized_queued_frames() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    let first = Message {
        kind: 1,
        payload: vec![1; frame::FRAGMENT_BYTES],
    };
    a.enqueue(first.clone(), now).unwrap();
    let packets = a.poll(now, 1).unwrap();
    assert_eq!(b.receive_authenticated(&packets[0], now).unwrap(), [first]);
    // One old-width open group and oversized queued data when PMTU shrinks.
    a.enqueue(
        Message {
            kind: 2,
            payload: vec![2; frame::FRAGMENT_BYTES * 2],
        },
        now,
    )
    .unwrap();
    a.set_datagram_limit(frame::MIN_UDP, now).unwrap();
    let small = Message {
        kind: 3,
        payload: vec![3; 3000],
    };
    a.enqueue(small.clone(), now).unwrap();
    let mut received = vec![];
    for ms in 0..1200 {
        let t = now + Duration::from_millis(ms);
        for packet in a.poll(t, 64).unwrap() {
            assert!(packet.len() + frame::DATAGRAM_OVERHEAD <= frame::MIN_UDP);
            received.extend(b.receive_authenticated(&packet, t).unwrap());
        }
        for packet in b.poll(t, 64).unwrap() {
            a.receive_authenticated(&packet, t).unwrap();
        }
    }
    assert_eq!(received, [small]);
    assert!(a.stats().queue_dropped > 0);
    assert_eq!(a.stats().in_flight, 0);
}

#[test]
fn all_repair_modes_preserve_feedback_and_recover_only_when_enabled() {
    for fec in [false, true] {
        for rtx in [false, true] {
            let now = Instant::now();
            let policy = RepairConfig { fec, rtx };
            let mut a = Link::new(link(now).scope(), 10_000_000, now, policy).unwrap();
            // The receiver's outgoing policy must not disable decoding parity.
            let mut b = Link::new(
                link(now).scope(),
                10_000_000,
                now,
                RepairConfig {
                    fec: false,
                    rtx: false,
                },
            )
            .unwrap();
            let message = Message {
                kind: 2,
                payload: vec![7; frame::FRAGMENT_BYTES * 8],
            };
            a.enqueue(message.clone(), now).unwrap();
            let mut received = vec![];
            let mut lost = 0;
            for ms in 0..1300 {
                let at = now + Duration::from_millis(ms);
                for packet in a.poll(at, 64).unwrap() {
                    if matches!(
                        Frame::decode(&packet).unwrap(),
                        Frame::Source {
                            index: 0,
                            retransmitted: false,
                            ..
                        }
                    ) {
                        lost += 1;
                        continue;
                    }
                    received.extend(b.receive_authenticated(&packet, at).unwrap());
                }
                for packet in b.poll(at, 64).unwrap() {
                    a.receive_authenticated(&packet, at).unwrap();
                }
                assert!(a.stats().in_flight <= send::MAX_QUEUE);
            }
            assert_eq!(lost, 1);
            assert_eq!(a.stats().repair, policy);
            assert_eq!(received, if fec || rtx { vec![message] } else { vec![] });
            assert_eq!(a.stats().fec_sent > 0, fec);
            assert_eq!(b.stats().fec_recovered > 0, fec);
            assert_eq!(a.stats().retransmitted > 0, !fec && rtx);
            assert!(
                a.stats().acknowledged >= 7,
                "ACKs remain enabled in every mode"
            );
            assert_eq!(a.stats().in_flight, 0);
        }
    }
}

#[test]
fn repair_modes_bound_retries_even_without_feedback_and_with_nack_floods() {
    for fec in [false, true] {
        for rtx in [false, true] {
            let now = Instant::now();
            let mut a = Link::new(
                link(now).scope(),
                10_000_000,
                now,
                RepairConfig { fec, rtx },
            )
            .unwrap();
            a.enqueue(
                Message {
                    kind: 2,
                    payload: vec![8; frame::FRAGMENT_BYTES * 8],
                },
                now,
            )
            .unwrap();
            let mut originals = vec![];
            for ms in 0..2000 {
                let at = now + Duration::from_millis(ms);
                if !originals.is_empty() {
                    a.receive_authenticated(&Frame::Nack(originals.clone()).encode(), at)
                        .unwrap();
                }
                for bytes in a.poll(at, 64).unwrap() {
                    if let Frame::Source {
                        shard,
                        retransmitted: false,
                        ..
                    } = Frame::decode(&bytes).unwrap()
                    {
                        originals.push(Fragment::decode(&shard).unwrap().sequence);
                    }
                }
            }
            assert_eq!(a.stats().original_sent, 8);
            assert_eq!(a.stats().retransmitted > 0, rtx);
            assert!(
                a.stats().retransmitted <= 16,
                "at most two retries per source"
            );
            assert_eq!(a.stats().fec_sent > 0, fec);
            assert_eq!(a.stats().in_flight, 0);
            assert_eq!(a.stats().queued_bytes, 0);
        }
    }
}

#[test]
fn rejected_retry_backs_off_instead_of_requeueing_on_every_tick_or_nack() {
    let now = Instant::now();
    let mut a = Link::new(
        link(now).scope(),
        64_000,
        now,
        RepairConfig {
            fec: false,
            rtx: true,
        },
    )
    .unwrap();
    a.enqueue(
        Message {
            kind: 2,
            payload: vec![7; 100],
        },
        now,
    )
    .unwrap();
    let first = a.poll(now, 1).unwrap().pop().unwrap();
    let Frame::Source { shard, .. } = Frame::decode(&first).unwrap() else {
        panic!("source")
    };
    let sequence = Fragment::decode(&shard).unwrap().sequence;
    // Exhaust the rolling repair budget, without changing production timers.
    a.controller.charge(controller::Class::EarlyRtx, 1400, now);
    for ms in 1..450 {
        let at = now + Duration::from_millis(ms);
        a.receive_authenticated(&Frame::Nack(vec![sequence]).encode(), at)
            .unwrap();
        a.poll(at, 64).unwrap();
    }
    assert_eq!(a.stats().retransmitted, 0);
    assert!(
        (1..=4).contains(&a.stats().queue_dropped),
        "{:?}",
        a.stats().queue_dropped
    );
    // Once budget and backoff permit, retry remains usable; no permanent ban.
    for ms in 450..990 {
        a.poll(now + Duration::from_millis(ms), 64).unwrap();
    }
    assert!(a.stats().retransmitted > 0 && a.stats().retransmitted <= 2);
    a.poll(now + Duration::from_secs(2), 64).unwrap();
    assert_eq!(a.stats().in_flight, 0);
    assert_eq!(a.stats().queued_bytes, 0);
}

#[test]
fn received_feedback_never_funds_recursive_feedback() {
    let now = Instant::now();
    let mut a = link(now);
    a.controller.charge(controller::Class::Control, 1200, now);
    let ack = Frame::Ack(vec![
        Ack {
            sequence: u64::MAX,
            sent_us: 0,
            received_us: 0,
            arrival: Arrival::Original,
        };
        frame::MAX_FEEDBACK
    ]);
    for _ in 0..100 {
        a.receive_authenticated(&ack.encode(), now).unwrap();
        a.receive_authenticated(&Frame::Nack(vec![u64::MAX]).encode(), now)
            .unwrap();
    }
    assert!(a.receive_authenticated(&[255], now).is_err());
    assert!(a.sender.control(ack, now));
    assert!(a.poll(now, 64).unwrap().is_empty());
    assert_eq!(a.stats().tx_packets, 0);
}

#[test]
fn retained_epochs_share_one_pacer_and_one_repair_ledger() {
    let now = Instant::now();
    let scope = link(now).scope();
    let mut path = Controller::new(64_000, now);
    assert!(path.paced(controller::Class::EarlyRtx, 1400));
    assert!(path.protection_allows(controller::Class::EarlyRtx, 1400, 0));
    path.charge(controller::Class::EarlyRtx, 1400, now);
    let repair = RepairConfig {
        fec: false,
        rtx: true,
    };
    let mut epochs: Vec<_> = (1..=4)
        .map(|key_epoch| super::Link::new(FecScope { key_epoch, ..scope }, now, repair))
        .collect();
    for epoch in &mut epochs {
        epoch
            .enqueue(
                Message {
                    kind: 1,
                    payload: vec![1; 800],
                },
                now,
                &path,
            )
            .unwrap();
    }
    let total = epochs.iter().map(|e| e.load().0).sum();
    path.tick(now, total, true);
    let mut wire = 0;
    for epoch in &mut epochs {
        for bytes in epoch.poll(now, 64, &mut path).unwrap() {
            wire += bytes.len() + WIRE_OVERHEAD;
        }
    }
    assert!(
        wire > 0 && wire + 1400 <= 2400,
        "one initial burst, not four: {wire}"
    );
    assert!(epochs.iter().any(|e| e.stats(&path).original_sent == 0));
    // A new key has no permission to refund either pacing or protection charges.
    let mut replacement = super::Link::new(
        FecScope {
            key_epoch: 5,
            ..scope
        },
        now,
        repair,
    );
    replacement
        .enqueue(
            Message {
                kind: 1,
                payload: vec![2; 800],
            },
            now,
            &path,
        )
        .unwrap();
    assert!(replacement.poll(now, 64, &mut path).unwrap().is_empty());
    assert!(!path.protection_allows(controller::Class::EarlyRtx, 1, 0));
    // Each old/new source cache still belongs to its original key scope.
    for (index, epoch) in epochs.iter().enumerate() {
        assert_eq!(epoch.scope().key_epoch, index as u64 + 1);
        assert_eq!(epoch.stats(&path).in_flight, 1);
    }
}

#[test]
fn right_sized_parity_recovers_missing_short_or_long_sources_in_any_order() {
    for compact in [false, true] {
        for sizes in [
            [20, 100, 60, 200, 10, 120, 50, 90],
            [20, 800, 60, 900, 10, 120, 50, 90],
        ] {
            for missing in [0, 3] {
                for parity_first in [false, true] {
                    let now = Instant::now();
                    let policy = RepairConfig {
                        fec: true,
                        rtx: false,
                    };
                    let mut a = Link::new(link(now).scope(), 100_000_000, now, policy).unwrap();
                    let mut b = link(now);
                    if compact {
                        a.enable_compact();
                    }
                    let messages: Vec<_> = sizes
                        .iter()
                        .enumerate()
                        .map(|(i, &size)| Message {
                            kind: 2,
                            payload: vec![i as u8; size],
                        })
                        .collect();
                    for message in &messages {
                        a.enqueue(message.clone(), now).unwrap();
                    }
                    let mut packets = vec![];
                    for ms in 0..30 {
                        packets.extend(a.poll(now + Duration::from_millis(ms), 64).unwrap());
                    }
                    let expected_width = (sizes.iter().max().unwrap() + frame::FRAGMENT_HEADER)
                        .max(frame::MIN_SHARD_BYTES);
                    let mut parity_count = 0;
                    for packet in &packets {
                        if let Frame::Parity { shard, .. } = Frame::decode(packet).unwrap() {
                            assert_eq!(shard.len(), expected_width);
                            assert!(shard.len() < frame::SHARD_BYTES);
                            parity_count += 1;
                        }
                    }
                    assert!(parity_count > 0);
                    if parity_first {
                        packets.reverse();
                    }
                    let mut received = vec![];
                    for packet in packets {
                        if matches!(Frame::decode(&packet).unwrap(), Frame::Source { index, .. } if index == missing)
                        {
                            continue;
                        }
                        received.extend(
                            b.receive_authenticated(&packet, now + Duration::from_millis(30))
                                .unwrap(),
                        );
                    }
                    received.sort_by_key(|m| m.payload[0]);
                    assert_eq!(received, messages);
                    assert_eq!(
                        b.stats().fec_recovered,
                        if parity_first { parity_count } else { 1 }
                    );
                    assert_eq!(a.stats().retransmitted, 0);
                }
            }
        }
    }
}

#[test]
fn capability_upgrade_keeps_queued_source_format_and_exact_accounting() {
    let now = Instant::now();
    let mut a = link(now);
    let mut b = link(now);
    let messages = [
        Message {
            kind: 2,
            payload: vec![1; 100],
        },
        Message {
            kind: 2,
            payload: vec![2; 100],
        },
        Message {
            kind: 2,
            payload: vec![3; 4096],
        },
    ];
    a.enqueue(messages[0].clone(), now).unwrap();
    a.enable_compact();
    for message in &messages[1..] {
        a.enqueue(message.clone(), now).unwrap();
    }
    let mut received = vec![];
    let mut bytes = 0;
    let mut tags = vec![];
    for ms in 0..50 {
        for packet in a.poll(now + Duration::from_millis(ms), 64).unwrap() {
            bytes += packet.len() + frame::WIRE_OVERHEAD;
            tags.push(packet[0]);
            received.extend(
                b.receive_authenticated(&packet, now + Duration::from_millis(ms))
                    .unwrap(),
            );
        }
    }
    assert_eq!(tags[0], 1);
    assert!(tags.contains(&6));
    assert_eq!(a.stats().tx_wire_bytes, bytes as u64);
    received.sort_by_key(|m| m.payload[0]);
    assert_eq!(received, messages);
    let fresh = link(now);
    assert!(!fresh.supports_compact());
}
#[test]
fn young_cache_skips_scans_without_delaying_fec_or_retransmission() {
    let now = Instant::now();
    let mut a = link(now);
    a.enqueue(
        Message {
            kind: 1,
            payload: vec![7; 128],
        },
        now,
    )
    .unwrap();
    let first = a.poll(now, 64).unwrap();
    assert!(
        first
            .iter()
            .any(|b| matches!(Frame::decode(b).unwrap(), Frame::Source { .. }))
    );
    let closed = a.poll(now + Duration::from_millis(2), 64).unwrap();
    assert!(
        closed
            .iter()
            .any(|b| matches!(Frame::decode(b).unwrap(), Frame::Seal { .. }))
    );
    assert!(
        closed
            .iter()
            .any(|b| matches!(Frame::decode(b).unwrap(), Frame::Parity { .. }))
    );
    assert_eq!(a.stats().cache_scan_runs, 0);
    let due = now + a.controller.rto();
    let retry = a.poll(due, 64).unwrap();
    assert!(retry.iter().any(|b| matches!(
        Frame::decode(b).unwrap(),
        Frame::Source {
            retransmitted: true,
            ..
        }
    )));
    assert_eq!(a.stats().cache_scan_runs, 1);
    assert_eq!(a.stats().cache_scan_sources, 1);
    assert_eq!(a.stats().retransmitted, 1);
    a.poll(now + Duration::from_secs(1), 64).unwrap();
    assert_eq!(a.stats().in_flight, 0);
}
