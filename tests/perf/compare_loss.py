#!/usr/bin/env python3
"""Routed, packet-normalized comparison: clean control or seeded bidirectional loss.

Disable segmentation/coalescing on fixture veths, not on host interfaces or TUNs.
A router nft counter rejects results if oversized aggregated skbs reach the fault
boundary. Thus netem loss applies to actual <=1500-byte IP packets, not arbitrary
GSO groups. Compare loss against THIS routed clean control, not the direct suite.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform

from compare import Fixture, IMPLEMENTATIONS, measure, schedule, summarize, tool_info
from throughput import Network, digest, save


def check_packet_boundary(counters):
    entries = [entry['counter'] for entry in counters['nftables'] if 'counter' in entry]
    assert len(entries) == 1 and entries[0]['packets'] == 0, 'GSO aggregate reached per-packet loss boundary'


class RoutedFixture(Fixture):
    def router(self, *args, **kwargs):
        return self.ip('netns', 'exec', self.router_name, *args, **kwargs)

    def link(self, left, right, leftdev, rightdev, ipv4, ipv6=None):
        assert (left, right, leftdev, rightdev) == ('a', 'b', 'wan', 'wan')
        self.router_name = f'{self.token}-r'
        self.ip('netns', 'add', self.router_name)
        self.created.append(self.router_name)
        self.names['r'] = self.router_name
        try:
            self.ns('r', 'ip', 'link', 'set', 'lo', 'up')
            Network.link(self, 'a', 'r', 'wan', 'left', ['10.141.0.1/32', '10.141.0.254/32'],
                         ['fd10:141::1/128', 'fd10:141::fe/128'])
            Network.link(self, 'r', 'b', 'right', 'wan', ['10.141.0.253/32', '10.141.0.2/32'],
                         ['fd10:141::fd/128', 'fd10:141::2/128'])
            for node, remote, via, remote6, via6 in [
                ('a', '10.141.0.2', '10.141.0.254', 'fd10:141::2', 'fd10:141::fe'),
                ('b', '10.141.0.1', '10.141.0.253', 'fd10:141::1', 'fd10:141::fd'),
            ]:
                self.ns(node, 'ip', 'route', 'add', via + '/32', 'dev', 'wan')
                self.ns(node, 'ip', 'route', 'add', remote + '/32', 'via', via)
                self.ns(node, 'ip', '-6', 'route', 'add', via6 + '/128', 'dev', 'wan')
                self.ns(node, 'ip', '-6', 'route', 'add', remote6 + '/128', 'via', via6)
            for device, remote, remote6 in [('left', '10.141.0.1', 'fd10:141::1'),
                                             ('right', '10.141.0.2', 'fd10:141::2')]:
                self.ns('r', 'ip', 'route', 'add', remote + '/32', 'dev', device)
                self.ns('r', 'ip', '-6', 'route', 'add', remote6 + '/128', 'dev', device)
            self.ns('r', 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
            self.normalized_offloads = {}
            for node, device in [('a', 'wan'), ('b', 'wan'), ('r', 'left'), ('r', 'right')]:
                self.ns(node, 'ethtool', '-K', device, 'tso', 'off', 'gso', 'off', 'gro', 'off',
                        'tx-udp-segmentation', 'off', 'rx-udp-gro-forwarding', 'off')
                self.normalized_offloads[f'{node}/{device}'] = self.ns(node, 'ethtool', '-k', device).stdout
        finally:
            # Only endpoint nodes participate in Fixture.setup and process CPU accounting.
            del self.names['r']
        rule = self.directory / 'boundary.nft'
        rule.write_text('table inet comparison_boundary { counter oversized {}\n'
                        'chain check { type filter hook forward priority -100; policy accept; '
                        'meta length > 1500 counter name oversized; }\n}\n')
        self.router('nft', '-f', str(rule))

    def setup(self):
        super().setup()
        # Establish handshakes/PMTU first; all backends then warm up under the fault.
        for offset, device in enumerate(['left', 'right']):
            self.router('tc', 'qdisc', 'add', 'dev', device, 'root', 'netem', 'limit', '10000',
                        'delay', f'{self.args.delay_ms}ms', 'loss', 'random', f'{self.args.loss_percent}%',
                        'seed', str(self.args.seed + offset))

    def state(self):
        result = super().state()
        counters = json.loads(self.router('nft', '-j', 'list', 'counter', 'inet', 'comparison_boundary', 'oversized').stdout)
        check_packet_boundary(counters)
        result['router'] = dict(oversized=counters, offloads=self.normalized_offloads,
                                qdisc={dev: json.loads(self.router('tc', '-s', '-j', 'qdisc', 'show', 'dev', dev).stdout)
                                       for dev in ['left', 'right']})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--implementations', nargs='+', choices=IMPLEMENTATIONS, default=list(IMPLEMENTATIONS))
    parser.add_argument('--loss-percent', type=float, default=1)
    parser.add_argument('--delay-ms', type=int, default=10, help='one-way delay, also used in the loss=0 control')
    parser.add_argument('--seed', type=int, default=31415)
    parser.add_argument('--sample-ms', type=int, default=0, help='optional load-time diagnostics; 0 disables')
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--warmup', type=int, default=20)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--underlay-mbps', type=int, default=1000)
    parser.add_argument('--mtu', type=int, default=1280)
    parser.add_argument('--congestion', choices=['bbr', 'cubic', 'reno'], default='bbr')
    parser.add_argument('--output', type=Path, default=Path('target/perf-comparison-loss.json'))
    args = parser.parse_args()
    assert args.sample_ms == 0 or 100 <= args.sample_ms <= 5000
    assert 0 <= args.loss_percent <= 10 and 0 <= args.delay_ms <= 100
    assert 3 <= args.seconds <= 300 and 0 <= args.warmup <= 300 and 1 <= args.repeats <= 20
    assert 1 <= args.underlay_mbps <= 100_000 and 1280 <= args.mtu <= 1420
    assert len(args.implementations) == len(set(args.implementations))
    assert 0 <= args.seed <= 0xffffffff - args.repeats * 2
    seed = args.seed
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(complete=False, results=[], scope='same-host three-netns routed IPv4; packet-normalized veths, stock TUN offloads, both directions impaired after setup; warmup includes impairment; default nnlan FEC+RTX; not a same-feature comparison',
                  cpu_scope='100%=one logical core; no attributed CPU for kernel/underlay; host CPU contains unrelated work',
                  provenance=dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                    binary_sha256=digest(args.binary), logical_cpus=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)),
                    cpu_model=next(line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                                   if line.startswith('model name')), loadavg=os.getloadavg(),
                    source_sha256={str(p): digest(p) for p in [Path(__file__), Path(__file__).with_name('compare.py'),
                        Path(__file__).with_name('throughput.py'), Path(__file__).with_name('load_sampler.py'), Path(__file__).parents[1]/'e2e/netns_fixture.py']},
                    tools={name: tool_info(name, '--version') for name in ['wg', 'wireguard-go', 'iperf3', 'ethtool']},
                    arguments={k: str(v) if isinstance(v, Path) else v for k,v in vars(args).items()}))
    save(args.output, report)
    try:
        for repeat, implementation, case in schedule(args.implementations, ['ipv4'], args.repeats):
            args.seed = seed + repeat * 2
            with RoutedFixture(args, implementation) as net:
                net.setup()
                result = dict(repeat=repeat, implementation=implementation, case=case, seed=args.seed,
                              namespace_prefix=net.token, **measure(net, args, case))
                if args.loss_percent:
                    dropped = sum(q['drops'] for queues in result['after']['router']['qdisc'].values() for q in queues)
                    assert dropped > 0, 'loss injection did not drop any packets'
            result['cleanup_complete'] = True
            report['results'].append(result)
            report['summary'] = summarize(report['results'])
            save(args.output, report)
            print(json.dumps({k: result[k] for k in ['implementation','repeat','receiver_mbps','daemon_cpu_percent']}
                             | dict(rtt_ms=result['loaded_icmp']['rtt_ms'])), flush=True)
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        save(args.output, report)
        raise
    report['complete'] = True
    report['provenance']['finished_at'] = datetime.now(timezone.utc).isoformat()
    save(args.output, report)


if __name__ == '__main__':
    main()
