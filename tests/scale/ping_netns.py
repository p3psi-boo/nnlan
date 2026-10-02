#!/usr/bin/env python3
"""Fixed-count scale-probe regression: delayed replies and deterministic loss."""
import argparse
import hashlib
import json
from pathlib import Path
from tun_scale import Network, ping_command, require_ping


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--output', type=Path, default=Path('target/scale-ping-netns.json'))
    args = parser.parse_args()
    report = dict(ok=False, scope='direct underlay only; no overlay daemon', cases=[])
    net = Network(args.binary, ['a', 'b'])
    try:
        with net:
            report['namespace_prefix'] = net.token
            net.link('a', 'b', 'underlay', 'underlay',
                     ['10.254.254.1/30', '10.254.254.2/30'], ['fdff::1/64', 'fdff::2/64'])
            report['ping_version'] = net.ns('a', 'ping', '-V').stdout
            for node in ['a', 'b']:
                net.ns(node, 'tc', 'qdisc', 'add', 'dev', 'underlay', 'root', 'netem', 'delay', '150ms')
            for loss in [False, True]:
                if loss:
                    net.ns('b', 'tc', 'qdisc', 'replace', 'dev', 'underlay', 'root', 'netem', 'loss', '100%')
                for family, address in [('4', '10.254.254.2'), ('6', 'fdff::2')]:
                    command = ping_command(family, address)
                    result = net.ns('a', *command, timeout=5, check=False)
                    accepted = require_ping(result, 3)
                    report['cases'].append(dict(loss=loss, command=command, accepted=accepted,
                                                exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
                    assert accepted == (not loss), report['cases'][-1]
                    assert '3 packets transmitted' in result.stdout
                    if not loss:
                        assert all(f'icmp_seq={n} ' in result.stdout for n in [1, 2, 3])
            report['ok'] = True
    finally:
        remaining = net.ip('netns', 'list').stdout.split()
        report['all_owned_namespaces_removed'] = all(n not in remaining for n in net.names.values())
        report['fixture_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in [Path(__file__), Path(__file__).with_name('tun_scale.py')]}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    assert report['all_owned_namespaces_removed']


if __name__ == '__main__':
    main()
