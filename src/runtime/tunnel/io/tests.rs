use super::*;

#[test]
fn aggregate_tail_survives_multiple_scheduler_turns() {
    let mut reader = Reader::new(1280);
    reader.count = READ_BATCH;
    for i in 0..READ_BATCH {
        reader.packets[i][0] = i as u8;
        reader.sizes[i] = 1;
    }
    for turn in 0..4 {
        for index in 0..32 {
            assert_eq!(reader.next(), Some(&[(turn * 32 + index) as u8][..]));
        }
        assert_eq!(reader.count - reader.next, READ_BATCH - (turn + 1) * 32);
    }
    assert!(reader.next().is_none());
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|b| u32::from(b[0]) * 256 + u32::from(*b.get(1).unwrap_or(&0)))
        .sum();
    while sum > 65535 {
        sum = (sum >> 16) + (sum & 65535);
    }
    !(sum as u16)
}

fn packet(protocol: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let header = if protocol == 6 { 20 } else { 8 };
    let mut packet = vec![0; 20 + header + payload.len()];
    packet[0] = 0x45;
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[10, 222, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 222, 0, 1]);
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20..22].copy_from_slice(&5555_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&40123_u16.to_be_bytes());
    if protocol == 6 {
        packet[24..28]
            .copy_from_slice(&(1000 + u32::from(id) * payload.len() as u32).to_be_bytes());
        packet[28..32].copy_from_slice(&77_u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x10; // ACK, no options or sequence boundary flags.
        packet[34..36].copy_from_slice(&4096_u16.to_be_bytes());
    } else {
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    packet[20 + header..].copy_from_slice(payload);
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&((header + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&packet[20..]);
    let sum = checksum(&pseudo);
    let at = if protocol == 6 { 36 } else { 26 };
    packet[at..at + 2].copy_from_slice(&sum.to_be_bytes());
    packet
}

#[test]
fn writer_capacity_actually_enables_gro_and_invalid_checksums_do_not_merge() {
    for protocol in [6, 17] {
        let mut writer = Writer::new(1280);
        for id in 0..WRITE_BATCH {
            writer.push(&packet(protocol, id as u16, &[7; 100]));
        }
        writer
            .gro
            .apply_gro(
                &mut writer.packets[..writer.count],
                VIRTIO_NET_HDR_LEN,
                true,
            )
            .unwrap();
        let header = if protocol == 6 { 40 } else { 28 };
        assert_eq!(
            writer.packets.iter().map(Vec::len).max(),
            Some(VIRTIO_NET_HDR_LEN + header + WRITE_BATCH * 100)
        );
        assert!(
            writer
                .packets
                .iter()
                .all(|p| p.capacity() <= writer.capacity)
        );

        let mut writer = Writer::new(1280);
        writer.push(&packet(protocol, 0, &[7; 100]));
        let mut bad = packet(protocol, 1, &[7; 100]);
        *bad.last_mut().unwrap() ^= 1;
        writer.push(&bad);
        writer
            .gro
            .apply_gro(
                &mut writer.packets[..writer.count],
                VIRTIO_NET_HDR_LEN,
                true,
            )
            .unwrap();
        assert!(
            writer.packets[..2]
                .iter()
                .all(|p| p.len() == VIRTIO_NET_HDR_LEN + header + 100)
        );
        // Invalid input remains an ordinary packet for kernel checksum rejection.
        assert_eq!(writer.packets[1][0], 0);
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "run via tests/e2e/tun_io_netns.py in its owned namespace"]
async fn kernel_plain_and_offloaded_tun_deliver_packets() {
    assert_eq!(std::env::var("NNLAN_IO_TEST_NETNS").as_deref(), Ok("owned"));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap()
    );
    for offload in [false, true] {
        let device = tun_rs::DeviceBuilder::new()
            .name("nniotest0")
            .ipv4("10.222.0.1", 24, None)
            .mtu(1280)
            .offload(offload)
            .enable(true)
            .build_async()
            .unwrap();
        assert_eq!(device.tcp_gso(), offload);
        let socket = tokio::net::UdpSocket::bind("10.222.0.1:40123")
            .await
            .unwrap();
        let mut writer = Writer::new(1280);
        for id in 0..32 {
            writer
                .send(&device, &packet(17, id, &[id as u8; 100]))
                .await
                .unwrap();
        }
        writer.flush(&device).await.unwrap();
        let mut received = std::collections::BTreeSet::new();
        let mut buf = [0; 2048];
        for _ in 0..32 {
            let (len, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(peer.to_string(), "10.222.0.2:5555");
            assert_eq!(len, 100);
            assert_eq!(buf[..len], vec![buf[0]; len]);
            assert!(received.insert(buf[0]));
        }
        assert_eq!(received.len(), 32);
        socket
            .send_to(b"kernel reply", "10.222.0.2:5555")
            .await
            .unwrap();
        let mut reader = Reader::new(1280);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                reader.ready(&device).await.unwrap();
                if reader.next().unwrap().ends_with(b"kernel reply") {
                    break;
                }
            }
        })
        .await
        .unwrap();
        drop(socket);
        drop(device);
    }
}
