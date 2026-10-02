#!/usr/bin/env python3
"""One-variable TUN queue experiment, not a production fix or competitor score.
Uses the routed no-injected-loss control with 20 ms base RTT. All changes are
limited to the fixture's nnlan0 devices; defaults keep the existing queue length.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from compare import measure, tool_info
from compare_loss import RoutedFixture
from throughput import digest, save


class DiagnosticFixture(RoutedFixture):
    def setup(self):
        super().setup()
        if self.args.tun_queue is not None:
            for node in self.names:
                self.ns(node, 'ip', 'link', 'set', 'dev', self.devices[node],
                        'txqueuelen', str(self.args.tun_queue))

    def state(self):
        state = super().state()
        for node in self.names:
            state[node]['netstat'] = self.ns(node, 'cat', '/proc/net/netstat').stdout
            state[node]['snmp'] = self.ns(node, 'cat', '/proc/net/snmp').stdout
            state[node]['tun_qdisc'] = json.loads(self.ns(node, 'tc', '-s', '-j', 'qdisc', 'show', 'dev', self.devices[node]).stdout)
            state[node]['wan'] = json.loads(self.ns(node, 'ip', '-s', '-j', 'link', 'show', 'dev', 'wan').stdout)
        return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--tun-queue', type=int, choices=[500, 1024, 2048])
    parser.add_argument('--output', type=Path, default=Path('target/perf-tun-diagnose.json'))
    args = parser.parse_args()
    args.underlay_mbps, args.mtu, args.delay_ms, args.loss_percent = 1000, 1280, 10, 0
    args.seed, args.warmup, args.seconds, args.congestion = 31415, 20, 15, 'bbr'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(complete=False, scope=__doc__, started_at=datetime.now(timezone.utc).isoformat(),
                  binary_sha256=digest(args.binary), tun_queue=args.tun_queue,
                  tools={name: tool_info(name, '--version') for name in ['iperf3', 'ethtool']},
                  arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                  helper_sha256=digest(Path(__file__).parents[1] / 'e2e/netns_fixture.py'),
                  source_sha256={p: digest(Path(__file__).with_name(p)) for p in
                                 ['diagnose_tun.py', 'compare_loss.py', 'compare.py', 'throughput.py']})
    save(args.output, report)
    try:
        with DiagnosticFixture(args, 'nnlan') as net:
            report['namespace_prefix'] = net.token
            net.setup()
            report['result'] = measure(net, args, 'ipv4')
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        save(args.output, report)
        raise
    report['cleanup_complete'] = True
    report['complete'] = True
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    save(args.output, report)
    result = report['result']
    print(json.dumps(dict(mbps=result['receiver_mbps'], rtt_ms=result['loaded_icmp']['rtt_ms'],
                          tcp_retransmits=result['iperf']['end']['sum_sent']['retransmits'],
                          tun_tx_drops={n: result['after'][n]['link'][0]['stats64']['tx']['dropped'] -
                                        result['before'][n]['link'][0]['stats64']['tx']['dropped'] for n in ['a','b']})))


if __name__ == '__main__':
    main()
