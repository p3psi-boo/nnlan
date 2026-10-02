"""Dual-stack UDP stream with exact payload validation and same-kernel timestamps."""
import argparse
import json
import math
from pathlib import Path
import selectors
import socket
import struct
import time

HEADER = struct.Struct("!8sQQ")
PAYLOAD = bytes(n % 251 for n in range(768 - HEADER.size))
PORT = 34678


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["send", "receive"])
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ipv6", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--interval", type=float, default=0.01)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tag = bytes.fromhex(args.tag)
    assert len(tag) == 8 and 10 <= args.count <= 10000 and args.interval > 0
    sockets = [(4, socket.socket(socket.AF_INET, socket.SOCK_DGRAM), args.ipv4),
               (6, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM), args.ipv6)]
    try:
        if args.mode == "send":
            start = time.monotonic()
            for seq in range(args.count):
                time.sleep(max(0, start + seq * args.interval - time.monotonic()))
                for _, sock, address in sockets:
                    body = HEADER.pack(tag, seq, time.monotonic_ns()) + PAYLOAD
                    assert sock.sendto(body, (address, PORT)) == len(body)
            args.output.write_text(json.dumps(dict(sent_per_family=args.count, elapsed=time.monotonic()-start)))
            return
        poll = selectors.DefaultSelector()
        samples = {family: {} for family, _, _ in sockets}
        duplicates = {4: 0, 6: 0}
        reordered = {4: 0, 6: 0}
        highest = {4: -1, 6: -1}
        for family, sock, address in sockets:
            if family == 6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, PORT))
            sock.setblocking(False)
            poll.register(sock, selectors.EVENT_READ, family)
        args.output.with_suffix(".ready").write_text("ready")
        deadline = time.monotonic() + args.count * args.interval + 4
        while time.monotonic() < deadline:
            for key, _ in poll.select(timeout=0.1):
                body, source = key.fileobj.recvfrom(65535)
                family = key.data
                assert len(body) == 768 and body[HEADER.size:] == PAYLOAD, "damaged payload"
                received_tag, seq, sent = HEADER.unpack_from(body)
                assert received_tag == tag and seq < args.count, "unexpected stream"
                assert time.monotonic_ns() >= sent
                if seq in samples[family]:
                    duplicates[family] += 1
                else:
                    samples[family][seq] = dict(delay_ms=(time.monotonic_ns()-sent)/1e6, source=source[0])
                    reordered[family] += int(seq < highest[family])
                    highest[family] = max(seq, highest[family])
        report = {}
        for family, received in samples.items():
            ordered = sorted(v["delay_ms"] for v in received.values())
            report[str(family)] = dict(received=len(received), lost=args.count-len(received),
                duplicates=duplicates[family], reordered=reordered[family],
                p_ms={str(p): ordered[max(0, math.ceil(len(ordered)*p/100)-1)] if ordered else None for p in [50, 99, 99.9]},
                samples=received)
        args.output.write_text(json.dumps(report))
    finally:
        for _, sock, _ in sockets:
            sock.close()


if __name__ == "__main__":
    main()
