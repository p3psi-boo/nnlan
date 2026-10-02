#!/usr/bin/env python3
"""Application datagram boundaries/checksums survive TUN GSO/GRO, in both families."""
import json
import socket
import struct
import sys
import time

mode, host = sys.argv[1:3]
family = socket.AF_INET6 if ':' in host else socket.AF_INET
port = 40123
with socket.socket(family, socket.SOCK_DGRAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    if mode == 'server':
        sock.bind((host, port))
        while True:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)
    else:
        sock.settimeout(5)
        sock.connect((host, port))
        report = []
        for phase, (size, count) in enumerate([(100, 128), (1200, 48), (900, 64)]):
            packets = [struct.pack('!II', phase, i) + bytes([i % 251]) * (size - 8) for i in range(count)]
            # Linux UDP_SEGMENT (uapi/linux/udp.h). No application retransmission:
            # missing GSO tail segments must fail, not be hidden by a retry loop.
            sent = sock.sendmsg([b''.join(packets)], [(socket.IPPROTO_UDP, 103, struct.pack('H', size))])
            assert sent == size * count
            remaining = set(packets)
            for _ in range(count):
                reply = sock.recv(65535)
                assert reply in remaining, 'corrupted, duplicated or coalesced application datagram'
                remaining.remove(reply)
            assert not remaining
            report.append(dict(size=size, sent=count, replies=count))
            time.sleep(.05)
        print(json.dumps(report))
