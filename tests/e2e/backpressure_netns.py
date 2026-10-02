#!/usr/bin/env python3
"""Bounded TUN ingress under overload: UDP/admin progress and policy revocation.

Owned three-node namespaces only. This is correctness, not a throughput benchmark.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--output', type=Path, default=Path('target/e2e-backpressure.json'))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(ok=False, binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  started_at=datetime.now(timezone.utc).isoformat(),
                  source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in [Path(__file__), Path(__file__).with_name('netns_fixture.py')]})
    try:
        with Network(args.binary, ['a', 'b', 'c']) as net:
            net.init(net.names)
            net.link('a', 'b', 'wanb', 'wan', ['10.149.0.1/30', '10.149.0.2/30'])
            net.link('a', 'c', 'wanc', 'wan', ['10.149.1.1/30', '10.149.1.2/30'])
            peers = ''.join(f'[[peers]]\nendpoint = "10.149.{i}.2:7331"\npublic_key = "{net.ids[n]}"\n'
                            for i, n in enumerate(['b', 'c']))
            net.paths['a'].write_text('name = "a"\nmax_neighbors = 2\nbandwidth_mbps = 2\n' + peers)
            for n in ['b', 'c']:
                net.paths[n].write_text(f'name = "{n}"\nmax_neighbors = 1\n')
            for n in net.names:
                net.start(n)
            net.wait(lambda: all(net.rpc(n, 'status')['nodes'] == 3 and
                                net.rpc(n, 'status')['kernel_routes_ready'] for n in net.names), 'TUN routes')
            before = net.rpc('a', 'status')
            addresses = {n: net.rpc(n, 'status')['address'] for n in net.names}
            net.ns('a', 'tc', 'qdisc', 'add', 'dev', 'wanb', 'root', 'netem', 'delay', '50ms')
            net.ns('b', 'tc', 'qdisc', 'add', 'dev', 'wan', 'root', 'netem', 'delay', '50ms')
            # Sink without ICMP port-unreachable traffic. Two address families.
            sink = "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0); s.bind(('::',40125))\nwhile True: s.recvfrom(2048)"
            net.spawn('b', [sys.executable, '-c', sink], net.directory / 'sink.log')
            net.wait(lambda: ':40125' in net.ns('b', 'ss', '-lnu').stdout, 'sink')
            flood = """import socket,sys,time
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM)
end=time.monotonic()+4
while time.monotonic()<end:
 for _ in range(16):
  try: s.sendto(bytes(1200),(sys.argv[1],40125))
  except OSError: pass
 time.sleep(.005)
"""
            trials = []
            for family in ['ipv4', 'ipv6']:
                child = net.spawn('a', [sys.executable, '-c', flood, addresses['b'][family]],
                                  net.directory / f'flood-{family}.log')
                # A busy TUN must not await admission inside send_ip and thereby
                # deadlock the UDP ACK/pacer or owner-only admin event branches.
                # Also probe the other path through actual kernel TUN ingress,
                # not just overlay RPC (which bypasses the ingress scheduler).
                time.sleep(.5)
                samples = []
                for _ in range(3):
                    started = time.monotonic()
                    state = net.rpc('a', 'status')
                    samples.append(dict(rpc_seconds=time.monotonic()-started, status=state))
                    probe = net.rpc('a', 'ping', net.ids['c'])
                    assert 'error' not in probe, probe
                    kernel_probe = net.ns('a', 'ping', '-4' if family == 'ipv4' else '-6',
                                          '-n', '-c', '3', '-i', '.02', '-W', '1', addresses['c'][family])
                    assert '3 packets transmitted, 3 received' in kernel_probe.stdout, kernel_probe.stdout
                    samples[-1]['kernel_probe'] = kernel_probe.stdout
                    queue = state['tun_backpressure']
                    assert queue['queued_bytes'] <= 32 * 1024 * 1024
                    assert queue['queued_packets'] <= 32768
                    assert queue['active_flows'] <= 256
                child.wait(timeout=8)
                assert child.returncode == 0
                assert max(s['rpc_seconds'] for s in samples) < 2
                assert all(s['status']['boot_id'] == before['boot_id'] for s in samples)
                assert any(s['status']['tun_backpressure']['pauses'] > 0 for s in samples)
                assert all(p['link']['transport_cached_sources'] <= 32768
                           for s in samples for p in s['status']['neighbors'])
                trials.append(dict(family=family, samples=samples))
            # Revoke a destination while more of its packets are waiting in TUN.
            child = net.spawn('a', [sys.executable, '-c', flood, addresses['b']['ipv4']],
                              net.directory / 'flood-revoke.log')
            time.sleep(.5)
            response = net.rpc('a', 'members', 'deny', net.ids['b'])
            assert 'error' not in response, response
            net.wait(lambda: all(p['node'] != net.ids['b'] for p in net.rpc('a', 'status')['neighbors']), 'revocation')
            probe = net.rpc('a', 'ping', net.ids['c'])
            assert 'error' not in probe, probe
            child.wait(timeout=8)
            assert child.returncode == 0
            # Other path and both IP families still work after the overload.
            for family, option in [('ipv4', '-4'), ('ipv6', '-6')]:
                net.ns('a', 'ping', option, '-n', '-c', '3', '-W', '2', addresses['c'][family])
            report.update(trials=trials, after=net.rpc('a', 'status'), revoked=True)
        report.update(ok=True, cleanup_complete=True)
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(ok=report['ok'], revoked=report['revoked'],
                          tun_backpressure=report['after']['tun_backpressure'])))


if __name__ == '__main__':
    main()
