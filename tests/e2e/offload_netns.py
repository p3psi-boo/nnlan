#!/usr/bin/env python3
"""Real UDP_SEGMENT application traffic across encrypted TUN; no host changes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--output', type=Path, default=Path('target/e2e-offload.json'))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(ok=False, started_at=datetime.now(timezone.utc).isoformat(),
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), trials=[])
    helper = Path(__file__).with_name('offload_traffic.py').resolve()
    report['source_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in [Path(__file__), helper, Path(__file__).with_name('netns_fixture.py')]}
    try:
        with Network(args.binary, ['a', 'b']) as net:
            net.init(net.names)
            net.link('a', 'b', 'wan', 'wan', ['10.148.0.1/30', '10.148.0.2/30'])
            net.paths['a'].write_text(f'name = "a"\nmax_neighbors = 1\n[[peers]]\nendpoint = "10.148.0.2:7331"\npublic_key = "{net.ids["b"]}"\n')
            net.paths['b'].write_text('name = "b"\nmax_neighbors = 1\n')
            for name in net.names:
                net.start(name)
            net.wait(lambda: all(net.rpc(n, 'status')['nodes'] == 2 and
                                net.rpc(n, 'status')['kernel_routes_ready'] for n in net.names), 'TUN routes')
            states = {n: net.rpc(n, 'status') for n in net.names}
            report['offloads'] = {n: net.ns(n, 'ethtool', '-k', 'nnlan0').stdout for n in net.names}
            report['interfaces'] = {n: json.loads(net.ns(n, 'ip', '-d', '-j', 'link', 'show', 'nnlan0').stdout) for n in net.names}
            for name in net.names:
                for family in [4, 6]:
                    host = states[name]['address'][f'ipv{family}']
                    net.spawn(name, [sys.executable, str(helper), 'server', host], net.directory / f'{name}-udp{family}.log')
            net.wait(lambda: all(net.ns(n, 'ss', '-lnu').stdout.count(':40123') == 2 for n in net.names), 'dual-stack UDP echoes')
            for origin, destination in [('a', 'b'), ('b', 'a')]:
                for family in [4, 6]:
                    host = states[destination]['address'][f'ipv{family}']
                    before = net.rpc(origin, 'status')
                    result = net.ns(origin, sys.executable, str(helper), 'client', host, timeout=20)
                    after = net.rpc(origin, 'status')
                    assert before['boot_id'] == after['boot_id']
                    report['trials'].append(dict(origin=origin, family=family, bursts=json.loads(result.stdout)))
        report['ok'] = True
        report['cleanup_complete'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
