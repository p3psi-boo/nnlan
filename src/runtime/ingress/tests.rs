use super::*;

fn udp(port: u16, size: usize) -> Vec<u8> {
    let mut p = vec![0; size];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    p[9] = 17;
    p[12..20].copy_from_slice(&[33, 1, 1, 1, 33, 1, 1, 2]);
    p[20..22].copy_from_slice(&port.to_be_bytes());
    p[22..24].copy_from_slice(&9999u16.to_be_bytes());
    p
}
fn distinct(q: &Ingress, first: &[u8], size: usize) -> Vec<u8> {
    (1..=u16::MAX)
        .map(|p| udp(p, size))
        .find(|p| q.bucket(p) != q.bucket(first))
        .unwrap()
}
fn check_accounting(q: &Ingress) {
    assert_eq!(
        q.stats.queued_bytes,
        q.flows.iter().map(|f| f.bytes).sum::<usize>()
    );
    assert_eq!(
        q.stats.queued_packets,
        q.flows.iter().map(|f| f.packets.len()).sum::<usize>()
    );
    assert_eq!(q.stats.active_flows, q.new.len() + q.old.len());
    let ids: std::collections::BTreeSet<_> = q.new.iter().chain(&q.old).collect();
    assert_eq!(ids.len(), q.stats.active_flows);
    for f in &q.flows {
        assert_eq!(
            f.bytes,
            f.packets.iter().map(|p| p.bytes.len()).sum::<usize>()
        );
        assert!(f.bytes <= MAX_BYTES);
    }
    assert!(q.stats.queued_bytes <= MAX_BYTES);
    assert!(q.stats.queued_packets <= MAX_PACKETS);
}

#[test]
fn classifier_uses_tuple_not_payload_ecn_or_fragment_payload() {
    let q = Ingress::new(1280);
    let a = udp(1234, 1200);
    let mut b = a.clone();
    b[1] = 3;
    b[24..].fill(99);
    assert_eq!(q.bucket(&a), q.bucket(&b));
    b[6] = 0x20; // First fragment: do not hash ports.
    let mut c = b.clone();
    c[6] = 0;
    c[7] = 1; // Later fragment, payload is not a transport header.
    c[20..].fill(42);
    assert_eq!(q.bucket(&b), q.bucket(&c));
    for len in 0..60 {
        for version in [0x4f, 0x60, 0xff] {
            q.bucket(&vec![version; len]);
        }
    }
    let mut v6 = vec![0; 80];
    v6[0] = 0x60;
    v6[6] = 44;
    let mut tail = v6.clone();
    tail[40..].fill(12);
    assert_eq!(q.bucket(&v6), q.bucket(&tail));
}

#[test]
fn blocked_flow_preserves_fifo_clock_and_does_not_block_other_flows() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 1200);
    let b = distinct(&q, &a, 80);
    q.enqueue(&a, now);
    let mut second = a.clone();
    second[30] = 1;
    q.enqueue(&second, now);
    q.enqueue(&b, now);
    let mut blocked = [false; FLOWS];
    let head = q.dequeue(now, &blocked).unwrap();
    assert_eq!(head.bytes, a);
    q.defer(head, &mut blocked);
    check_accounting(&q);
    assert_eq!(q.dequeue(now, &blocked).unwrap().bytes, b);
    assert!(q.dequeue(now, &blocked).is_none());
    let head = q
        .dequeue(now + Duration::from_millis(40), &[false; FLOWS])
        .unwrap();
    assert_eq!(head.at, now);
    assert_eq!(head.bytes, a);
    assert_eq!(
        q.dequeue(now + Duration::from_millis(40), &[false; FLOWS])
            .unwrap()
            .bytes,
        second
    );
    assert!(q.dequeue(now, &[false; FLOWS]).is_none());
    assert_eq!(q.stats.active_flows, 0);
    assert_eq!(q.stats.pauses, 1);
    check_accounting(&q);
}

#[test]
fn cold_gso_burst_is_not_dropped_and_drr_services_sparse_udp() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 1200);
    for _ in 0..64 {
        q.enqueue(&a, now);
    }
    // Consume one bulk packet, then introduce an ordinary new UDP flow.
    q.dequeue(now, &[false; FLOWS]).unwrap();
    let b = distinct(&q, &a, 80);
    q.enqueue(&b, now);
    let mut found = false;
    for _ in 0..3 {
        if q.dequeue(now, &[false; FLOWS]).unwrap().bytes == b {
            found = true;
            break;
        }
    }
    assert!(found);
    let mut served = 0;
    while q
        .dequeue(now + Duration::from_millis(30), &[false; FLOWS])
        .is_some()
    {
        served += 1;
    }
    assert!(served >= 61);
    assert_eq!(q.stats.dropped(), 0);
    check_accounting(&q);
}

#[test]
fn expiry_is_absolute_across_retries_and_releases_the_entire_queue() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 1200);
    for _ in 0..20 {
        q.enqueue(&a, now);
    }
    q.dequeue(now, &[false; FLOWS]).unwrap();
    for elapsed in [100, 200, 300, 499] {
        let packet = q
            .dequeue(now + Duration::from_millis(elapsed), &[false; FLOWS])
            .unwrap();
        assert_eq!(packet.at, now);
        q.defer(packet, &mut [false; FLOWS]);
    }
    assert_eq!(q.stats.dropped(), 0);
    assert!(q.dequeue(now + LIFETIME, &[false; FLOWS]).is_none());
    assert_eq!(q.stats.expired_packets, 19);
    assert!(q.is_empty());
    check_accounting(&q);
    q.enqueue(&a, now + LIFETIME);
    assert!(q.dequeue(now + LIFETIME, &[false; FLOWS]).is_some());
}

#[test]
fn hard_limits_bound_memory_and_protect_new_sparse_flow() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 1280);
    for _ in 0..MAX_BYTES / 1280 + 100 {
        q.enqueue(&a, now);
    }
    assert!(q.stats.overflow_dropped > 0);
    check_accounting(&q);
    for port in 1..(MAX_BYTES / 1280 + 100) as u16 {
        q.enqueue(&udp(port, 1280), now);
    }
    check_accounting(&q);
    let b = distinct(&q, &a, 80);
    q.enqueue(&b, now);
    assert!(q.flows[q.bucket(&b)].packets.iter().any(|p| p.bytes == b));
    assert!(q.stats.queued_bytes > MAX_BYTES - 1280);
    while q.dequeue(now + LIFETIME, &[false; FLOWS]).is_some() || !q.is_empty() {}
    q.dequeue(now + LIFETIME, &[false; FLOWS]);
    check_accounting(&q);
    for _ in 0..MAX_PACKETS + 100 {
        q.enqueue(&udp(1234, 24), now);
    }
    assert_eq!(q.stats.queued_packets, MAX_PACKETS);
    check_accounting(&q);
}

#[test]
fn long_flows_receive_byte_fair_service_not_equal_packet_counts() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 1280);
    let b = distinct(&q, &a, 320);
    for _ in 0..100 {
        q.enqueue(&a, now);
    }
    for _ in 0..400 {
        q.enqueue(&b, now);
    }
    let mut bytes = [0usize; 2];
    for _ in 0..100 {
        let packet = q.dequeue(now, &[false; FLOWS]).unwrap();
        let index = usize::from(packet.bytes.len() == 320);
        bytes[index] += packet.bytes.len();
    }
    assert!(bytes[0] > 0 && bytes[1] > 0);
    assert!(bytes[0].abs_diff(bytes[1]) <= 1280, "{bytes:?}");
    check_accounting(&q);
}

#[test]
fn hash_collisions_share_fifo_and_do_not_duplicate_scheduler_entries() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 80);
    let b = (1..=u16::MAX)
        .filter(|p| *p != 1234)
        .map(|p| udp(p, 80))
        .find(|p| q.bucket(p) == q.bucket(&a))
        .unwrap();
    q.enqueue(&a, now);
    q.enqueue(&b, now);
    assert_eq!(q.stats.active_flows, 1);
    let mut blocked = [false; FLOWS];
    let first = q.dequeue(now, &blocked).unwrap();
    q.defer(first, &mut blocked);
    assert!(q.dequeue(now, &blocked).is_none());
    assert_eq!(q.dequeue(now, &[false; FLOWS]).unwrap().bytes, a);
    assert_eq!(q.dequeue(now, &[false; FLOWS]).unwrap().bytes, b);
    assert!(q.dequeue(now, &[false; FLOWS]).is_none());
    check_accounting(&q);
}

#[test]
fn idle_bucket_releases_large_metadata_ring_but_remains_reusable() {
    let mut q = Ingress::new(1280);
    let now = Instant::now();
    let a = udp(1234, 80);
    let id = q.bucket(&a);
    for _ in 0..1024 {
        q.enqueue(&a, now);
    }
    assert!(q.flows[id].packets.capacity() >= 1024);
    while q.dequeue(now, &[false; FLOWS]).is_some() {}
    assert!(q.flows[id].packets.capacity() <= 128);
    q.enqueue(&a, now);
    assert_eq!(q.dequeue(now, &[false; FLOWS]).unwrap().bytes, a);
    assert!(q.dequeue(now, &[false; FLOWS]).is_none());
    check_accounting(&q);
}
