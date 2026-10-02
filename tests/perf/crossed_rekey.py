#!/usr/bin/env python3
"""Natural crossed LINK rekey followed by sustained real TUN TCP, not just echo.
Only owned namespaces: delay handshake datagrams, never application ciphertext.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import time

from throughput import Network, digest, latency, measure, save


def transition(net, report, output, initial):
    """No warmup exclusion at rotation: keep TCP and 50 ICMP/s live throughout."""
    seconds = 120
    host = initial['b']['address']['ipv4']
    tcp_log, ping_log = (net.directory / name for name in ['transition-tcp.json', 'transition-ping.log'])
    tcp = net.spawn('a', ['iperf3', '-c', host, '-J', '--get-server-output', '-t', str(seconds)], tcp_log)
    ping = net.spawn('a', ['ping', '-4', '-D', '-n', '-i', '0.02', '-c', str(seconds * 50), '-W', '2', host], ping_log)
    started = time.monotonic()
    capture = dict(complete=False, seconds=seconds, started=started, samples=[])
    report['transition'] = capture
    checkpoint = started
    while True:
        now = time.monotonic()
        states = {n: net.rpc(n, 'status') for n in net.paths}
        capture['samples'].append(dict(at=now, states=states))
        assert all(states[n]['boot_id'] == initial[n]['boot_id'] and states[n]['nodes'] == 2 for n in net.paths)
        if now >= checkpoint:
            save(output, report)
            checkpoint = now + 5
        if tcp.poll() is not None and ping.poll() is not None:
            break
        assert now - started < seconds + 30, 'continuous transition measurement timed out'
        time.sleep(0.2)
    capture['iperf'] = json.loads(tcp_log.read_text())
    capture['loaded_icmp'] = latency(ping_log.read_text())
    capture['finished'] = time.monotonic()
    assert tcp.returncode == 0 and 'error' not in capture['iperf'], capture['iperf']
    assert ping.returncode in [0, 1], capture['loaded_icmp']
    capture['minimum_observed_pmtu'] = min(s['states'][n]['neighbors'][0]['pmtu']['udp_payload']
                                           for s in capture['samples'] for n in net.paths)
    capture['complete'] = True
    save(output, report)


def delay_handshakes(net, name, wire_version):
    # Fixture underlay is IPv4 without options. Explicit IHL/protocol/port/magic
    # matches bind offsets to wire.rs: IPv4(20)+UDP(8)+GGBx(4), then kind/scope.
    # https://man7.org/linux/man-pages/man8/tc-u32.8.html
    # https://man7.org/linux/man-pages/man8/tc-prio.8.html
    net.ns(name, 'tc', 'qdisc', 'add', 'dev', 'wan', 'root', 'handle', '1:',
           'prio', 'bands', '3', 'priomap', *(['0'] * 16))
    net.ns(name, 'tc', 'qdisc', 'add', 'dev', 'wan', 'parent', '1:3',
           'handle', '30:', 'netem', 'delay', '100ms')
    for kind in [1, 2, 3]:
        net.ns(name, 'tc', 'filter', 'add', 'dev', 'wan', 'parent', '1:',
               'protocol', 'ip', 'prio', str(kind), 'u32',
               'match', 'ip', 'ihl', '5', '0xf',
               'match', 'ip', 'protocol', '17', '0xff',
               'match', 'ip', 'dport', '7331', '0xffff',
               'match', 'u32', hex(int.from_bytes(f'GGB{wire_version}'.encode(), 'big')), '0xffffffff', 'at', '28',
               'match', 'u8', str(kind), '0xff', 'at', '32',
               'match', 'u8', '0', '0xff', 'at', '33', 'flowid', '1:3')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--output', type=Path, default=Path('target/perf-crossed-rekey.json'))
    parser.add_argument('--wire-version', type=int, choices=[1, 2, 3], default=3, help='archived v1 binaries require 1; current protocol is 3')
    parser.add_argument('--transition', action='store_true', help='also measure continuous TCP/ICMP across the actual rotation, without excluding its warmup')
    args = parser.parse_args()
    args.seconds, args.warmup, args.perf = 10, 15, None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = dict(ok=False, scope='two real daemons/TUN, natural 120 s timer, handshake-only delay; bounded throughput regression, not full performance acceptance',
                  provenance=dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(), wire_version=args.wire_version,
                                  binary_sha256=digest(args.binary),
                                  fixture_sha256={p: digest(Path(__file__).parent / p) for p in ['crossed_rekey.py', 'throughput.py']},
                                  helper_sha256=digest(Path(__file__).parent.parent / 'e2e/netns_fixture.py')),
                  observations=[], post_rekey=[])
    save(args.output, report)
    try:
        with Network(args.binary, ['a', 'b']) as net:
            net.init(['a', 'b'])
            net.link('a', 'b', 'wan', 'wan', ['10.142.0.1/30', '10.142.0.2/30'])
            net.paths['a'].write_text(f'name = "a"\nmax_neighbors = 1\n[[peers]]\nendpoint = "10.142.0.2:7331"\npublic_key = "{net.ids["b"]}"\n')
            net.paths['b'].write_text('name = "b"\nmax_neighbors = 1\n')
            for name in net.paths:
                net.start(name)
            def states():
                return {n: net.rpc(n, 'status') for n in net.paths}
            net.wait(lambda: all(s['nodes'] == 2 and (p := s['neighbors'][0]['pmtu'])['udp_payload'] == p.get('maximum_udp_payload', 1232) for s in states().values()), 'initial full PMTU')
            initial = states()
            epochs = {n: s['neighbors'][0]['key_epoch'] for n, s in initial.items()}
            assert epochs['a'] == epochs['b'], 'single configured initial handshake'
            pids = {n: next(int(pid) for pid in net.ip('netns', 'pids', net.names[n]).stdout.split()
                           if Path(f'/proc/{pid}/comm').read_text().startswith('nnlan')) for n in net.paths}
            net.spawn('b', ['iperf3', '-s'], net.directory / 'iperf-server.log')
            net.wait(lambda: '5201' in net.ns('b', 'ss', '-ln', '-t').stdout, 'iperf server')
            address = initial['b']['address']
            report['baseline'] = measure(net, pids, args, 'overlay_ipv4', address['ipv4'], 0)
            assert report['baseline']['receiver_mbps'] >= 50, 'fixture must generate a high-rate flow'
            for n in net.paths:
                delay_handshakes(net, n, args.wire_version)
            if args.transition:
                transition(net, report, args.output, initial)
            deadline = time.monotonic() + 130
            while True:
                current = states()
                assert all(current[n]['boot_id'] == initial[n]['boot_id'] and current[n]['nodes'] == 2 for n in net.paths)
                new = {n: s['neighbors'][0]['key_epoch'] for n, s in current.items()}
                ready = all((p := s['neighbors'][0]['pmtu'])['udp_payload'] == p.get('maximum_udp_payload', 1232) for s in current.values())
                ready = ready and all(s['neighbors'][0]['link'].get('compact', True) for s in current.values())
                report['observations'].append(dict(at=time.monotonic(), epochs=new, full_pmtu=ready))
                save(args.output, report)
                if all(new[n] != epochs[n] for n in net.paths) and new['a'] != new['b'] and ready:
                    break
                assert time.monotonic() < deadline, 'natural rekey did not establish distinct outgoing epochs'
                time.sleep(1)
            report['crossed_epochs'] = new
            for index, case in enumerate(['overlay_ipv4', 'overlay_ipv6', 'overlay_ipv4_reverse']):
                trial = measure(net, pids, args, case, address['ipv6' if case == 'overlay_ipv6' else 'ipv4'], index + 1)
                report['post_rekey'].append(trial)
                save(args.output, report)
                for phase in ['before', 'after']:
                    assert all(trial[phase][n]['neighbors'][0]['key_epoch'] == new[n] for n in net.paths), 'measurement must stay on the crossed epochs'
                assert trial['receiver_mbps'] >= report['baseline']['receiver_mbps'] * 0.5, 'persistent crossed-epoch throughput collapse'
                assert trial['loaded_icmp']['samples'] == 500, 'lost overlay echo under sustained load'
            report['qdiscs'] = {n: json.loads(net.ns(n, 'tc', '-s', '-j', 'qdisc', 'show', 'dev', 'wan').stdout) for n in net.paths}
            for rows in report['qdiscs'].values():
                delayed = next(q for q in rows if q['handle'] == '30:')
                assert 3 <= delayed['packets'] <= 64, 'delay must affect handshakes, not bulk data'
            if args.transition:
                capture = report['transition']
                original = {n: initial[n]['neighbors'][0]['key_epoch'] for n in net.paths}
                observed = [{n: sample['states'][n]['neighbors'][0]['key_epoch'] for n in net.paths}
                            for sample in capture['samples']]
                assert observed[0] == original and observed[-1] == new, 'continuous load must span the actual rekey'
                assert capture['minimum_observed_pmtu'] == min(s['neighbors'][0]['pmtu']['udp_payload'] for s in initial.values()), 'same-path rekey regressed proven PMTU'
                assert capture['loaded_icmp']['samples'] == capture['seconds'] * 50, 'lost overlay echo during continuous rekey load'
        report['ok'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['provenance']['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(args.output, report)


if __name__ == '__main__':
    main()
