#!/usr/bin/env python3
"""Same-protocol rolling upgrade: archived and new binaries exchange real TUN traffic."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from netns_fixture import Network


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-binary', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--output', type=Path, default=Path('target/e2e-compatibility.json'))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(ok=False, started_at=datetime.now(timezone.utc).isoformat(),
                  binary_sha256={n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in [('old', args.old_binary), ('new', args.binary)]},
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), echoes=[])
    try:
        with Network(args.binary, ['a', 'b']) as net:
            net.init(net.names)
            net.link('a', 'b', 'wan', 'wan', ['10.147.0.1/30', '10.147.0.2/30'])
            net.paths['a'].write_text(f'name = "a"\nmax_neighbors = 1\n[[peers]]\nendpoint = "10.147.0.2:7331"\npublic_key = "{net.ids["b"]}"\n')
            net.paths['b'].write_text('name = "b"\nmax_neighbors = 1\n')
            net.daemons['a'] = net.spawn('a', [str(args.old_binary.resolve()), '--config', str(net.paths['a']), 'run'], net.paths['a'].with_suffix('.log'))
            net.start('b')
            net.wait(lambda: all(net.rpc(n, 'status')['nodes'] == 2 and net.rpc(n, 'status')['kernel_routes_ready'] for n in net.names), 'mixed-version convergence')
            states = {n: net.rpc(n, 'status') for n in net.names}
            common = min(s['neighbors'][0]['pmtu'].get('maximum_udp_payload', 1232)
                         for s in states.values())
            net.wait(lambda: all(net.rpc(n, 'status')['neighbors'][0]['pmtu']['udp_payload'] == common
                                 for n in net.names), 'exact common PMTU')
            if states['b']['neighbors'][0]['pmtu'].get('maximum_udp_payload', 1232) > common:
                net.wait(lambda: net.rpc('b', 'status')['neighbors'][0]['pmtu']['failed_sizes'] > 0,
                         'legacy peer ignores extension probe without losing working size')
            capability = {n: net.rpc(n, 'status')['neighbors'][0]['link'].get('compact') for n in net.names}
            if capability['a'] is None:
                assert capability['b'] in (None, False), 'PMTU proof is not format capability'
            report['compact_capability'] = capability
            report['common_udp_payload'] = common
            report['pmtu'] = {n: net.rpc(n, 'status')['neighbors'][0]['pmtu'] for n in net.names}
            assert all(p['udp_payload'] == common for p in report['pmtu'].values())
            for n in net.names:
                net.spawn(n, ['iperf3', '-s'], net.directory / f'{n}-tcp.log')
            net.wait(lambda: all('5201' in net.ns(n, 'ss', '-lnt').stdout for n in net.names), 'TCP servers')
            for origin, target in [('a', 'b'), ('b', 'a')]:
                status = net.rpc(target, 'status')
                assert status['wire_protocol'] == 'GGB3'
                echo = net.rpc(origin, 'ping', target, '--size', '16384')
                assert echo['hop_encrypted'] and echo['bytes'] == 16384
                trace = net.rpc(origin, 'trace', target)
                assert trace['complete'] and [h['node'] for h in trace['hops']] == [net.ids[target]]
                pings = {}
                transfers = {}
                for family in [4, 6]:
                    # Exercise full TUN MTU, including link fragmentation on the older peer.
                    size = '1252' if family == 4 else '1232'
                    host = status['address'][f'ipv{family}']
                    result = net.ns(origin, 'ping', f'-{family}', '-M', 'do', '-s', size, '-n', '-c', '3', '-W', '3', host)
                    assert re.search(r'\b0% packet loss', result.stdout), result.stdout
                    pings[f'ipv{family}'] = result.stdout
                    trial = json.loads(net.ns(origin, 'iperf3', '-c', host, '-J', '-t', '2').stdout)
                    assert 'error' not in trial and trial['end']['sum_received']['bytes'] > 0
                    transfers[f'ipv{family}'] = trial
                report['echoes'].append(dict(origin=origin, echo=echo, trace=trace, pings=pings, tcp=transfers))
            def drained():
                link = net.rpc('b', 'status')['neighbors'][0]['link']
                return (not link['control']['fec_suppressed'] and
                        link['in_flight'] == 0 and link['queued_data_packets'] == 0)
            net.wait(drained, 'quiescent sender with FEC resumed after TCP load')
            # Normalize at the veth boundary, before the receiver's input hook.
            # A 128-byte diagnostic echo source is exactly 313 IPv4 bytes:
            # IP/UDP 28 + session/tag 40 + source 19 + fragment 23 + envelope 66
            # + echo kind/request ID 9 + application 128. RTX has the same size.
            # Drop ALL of these sources and retries. Only parity may repair them.
            for name in net.names:
                net.ns(name, 'ethtool', '-K', 'wan', 'tso', 'off', 'gso', 'off', 'gro', 'off',
                       'tx-udp-segmentation', 'off', 'rx-udp-gro-forwarding', 'off')
            rules = net.directory / 'legacy-fec.nft'
            rules.write_text('table inet legacy_fec { counter sources {}\n '
                             'chain input { type filter hook input priority -10; policy accept; '
                             'ip saddr 10.147.0.2 udp dport 7331 meta length 313 counter name sources drop; }\n}\n')
            net.ns('a', 'nft', '-f', str(rules))
            baseline = net.rpc('a', 'status')['neighbors'][0]['link']['fec_recovered']
            repair = []
            for _ in range(8):
                echo = net.rpc('b', 'ping', 'a', '--size', '128')
                assert echo['hop_encrypted'] and echo['bytes'] == 128
                repair.append(echo)
            recovered = net.rpc('a', 'status')['neighbors'][0]['link']['fec_recovered'] - baseline
            counters = json.loads(net.ns('a', 'nft', '-j', 'list', 'counter', 'inet', 'legacy_fec', 'sources').stdout)
            dropped = sum(row['counter']['packets'] for row in counters['nftables'] if 'counter' in row)
            report['legacy_fec_recovered'] = recovered
            report['source_drop_counter'] = counters
            report['loss_echoes'] = repair
            assert dropped >= 8 and recovered >= 8, 'old peer must repair deliberately missing new sources'
            net.ns('a', 'nft', 'delete', 'table', 'inet', 'legacy_fec')
        report['cleanup_complete'] = True
        report['ok'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
