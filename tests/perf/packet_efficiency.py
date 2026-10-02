#!/usr/bin/env python3
"""Fixed-rate UDP payload versus accounted protocol bytes, not a capacity benchmark."""
import argparse
from datetime import datetime, timezone
import json
import platform
from pathlib import Path
import time

from compare import Fixture, tool_info
from throughput import digest, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--length', type=int, default=1200)
    parser.add_argument('--offered-mbps', type=int, default=100)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--warmup', type=int, default=20)
    parser.add_argument('--output', type=Path, default=Path('target/packet-efficiency.json'))
    args = parser.parse_args()
    assert 32 <= args.length <= 1252 and 1 <= args.offered_mbps <= 1000
    assert 3 <= args.seconds <= 300 and 0 <= args.warmup <= 300
    args.underlay_mbps, args.mtu, args.congestion = 1000, 1280, 'bbr'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(ok=False, started_at=datetime.now(timezone.utc).isoformat(),
                  binary_sha256=digest(args.binary), kernel=platform.release(),
                  iperf_tool=tool_info("iperf3", "--version"),
                  source_sha256={str(p): digest(p) for p in [Path(__file__), Path(__file__).with_name('compare.py'),
                        Path(__file__).with_name('throughput.py'), Path(__file__).parents[1]/'e2e/netns_fixture.py']},
                  arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                  scope='one fixed-rate IPv4 UDP flow; 1000 Mbit/s shaped underlay; MTU 1280; '
                        'default FEC/RTX; software wire-budget counters include IPv6 overhead even on IPv4; '
                        'not physical NIC bytes or maximum throughput')
    try:
        with Fixture(args, 'nnlan') as net:
            net.setup()
            command = ['iperf3', '-c', net.hosts['ipv4'], '-u', '-b', f'{args.offered_mbps}M',
                       '-l', str(args.length), '-J', '--get-server-output']
            if args.warmup:
                report['warmup'] = json.loads(net.ns('a', *command, '-t', str(args.warmup),
                                                     timeout=args.warmup + 20).stdout)
                assert 'error' not in report['warmup']
            before = net.state()
            started = time.monotonic()
            trial = json.loads(net.ns('a', *command, '-t', str(args.seconds), timeout=args.seconds + 20).stdout)
            elapsed = time.monotonic() - started
            assert 'error' not in trial, trial
            after = net.state()
            # Require an actual receiving summary, never silently substitute a sender rate.
            receiver = trial['end'].get('sum_received')
            if receiver is None:
                receiver = trial['server_output_json']['end']['sum']
            assert receiver['sender'] is False and receiver['bytes'] > 0, receiver
            report.update(before=before, after=after, iperf=trial, seconds=elapsed,
                          receiver_mbps=receiver['bits_per_second'] / 1e6,
                          received_bytes=receiver['bytes'], reported_packets=receiver['packets'],
                          lost_packets=receiver['lost_packets'], lost_percent=receiver['lost_percent'])
            deltas = {}
            for n in net.names:
                b, a = before[n]['nnlan'], after[n]['nnlan']
                assert b['boot_id'] == a['boot_id']
                assert b['neighbors'][0]['key_epoch'] == a['neighbors'][0]['key_epoch']
                assert a['neighbors'][0]['link']['repair'] == dict(fec=True, rtx=True)
                old, new = b['neighbors'][0]['link'], a['neighbors'][0]['link']
                deltas[n] = {k: new[k]-old[k] for k in ['tx_wire_bytes', 'tx_packets', 'original_sent',
                              'fec_sent', 'retransmitted', 'queue_dropped', 'unsent_sources_dropped']}
                deltas[n]['daemon_dropped'] = a['dropped']-b['dropped']
                deltas[n]['tun_tx_dropped'] = after[n]['link'][0]['stats64']['tx']['dropped']-before[n]['link'][0]['stats64']['tx']['dropped']
            report['daemon_logs'] = {n: net.paths[n].with_suffix('.log').read_text() for n in net.names}
            report['deltas'] = deltas
            report['sender_accounted_bytes_per_received_byte'] = deltas['a']['tx_wire_bytes'] / receiver['bytes']
        report['cleanup_complete'] = True
        report['ok'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(args.output, report)
    print(json.dumps({k: report[k] for k in ['ok', 'receiver_mbps', 'lost_percent', 'sender_accounted_bytes_per_received_byte', 'deltas']}))


if __name__ == '__main__':
    main()
