#!/usr/bin/env python3
"""Same-host direct-path comparison; one active flow, fresh owned netns per trial.

WireGuard is a dataplane reference, not a replacement for nnlan's FEC/relay stack.
No accounts, coordination servers, host routes, firewall rules or sysctls needed.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import time

from throughput import Network, digest, latency, save, ticks
from load_sampler import LoadSampler

IMPLEMENTATIONS = ('underlay', 'nnlan', 'wireguard-kernel', 'wireguard-go')
CASES = ('ipv4', 'ipv6', 'ipv4_reverse')


def schedule(implementations, cases, repeats):
    # Rotate both implementation and direction order; never overlap active trials.
    for repeat in range(repeats):
        impls = implementations[repeat % len(implementations):] + implementations[:repeat % len(implementations)]
        directions = cases[repeat % len(cases):] + cases[:repeat % len(cases)]
        for case in directions:
            for implementation in impls:
                yield repeat, implementation, case


def host_cpu():
    # Whole-host context only, NOT attributable CPU for kernel WireGuard.
    return list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))


def cpu_percent(before, after, elapsed):
    # user + nice + system + irq + softirq; idle/iowait/steal are not work.
    return sum(after[i] - before[i] for i in (0, 1, 2, 5, 6)) / os.sysconf('SC_CLK_TCK') / elapsed * 100


def tool_info(name, *version_args):
    path = Path(shutil.which(name) or name).resolve(strict=True)
    version = subprocess.run([str(path), *version_args], capture_output=True, text=True, check=True, timeout=10)
    return dict(path=str(path), sha256=digest(path), version=version.stdout.strip())


class Fixture(Network):
    def __init__(self, args, implementation):
        super().__init__(args.binary, ['a', 'b'])
        self.args, self.implementation = args, implementation
        self.devices, self.pids, self.uapi = {}, {}, []

    def setup(self):
        self.link('a', 'b', 'wan', 'wan', ['10.141.0.1/30', '10.141.0.2/30'],
                  ['fd10:141::1/64', 'fd10:141::2/64'])
        burst = max(65536, self.args.underlay_mbps * 1_000_000 // 8 // 200)
        for node in self.names:
            self.ns(node, 'tc', 'qdisc', 'add', 'dev', 'wan', 'root', 'tbf',
                    'rate', f'{self.args.underlay_mbps}mbit', 'burst', str(burst), 'latency', '20ms')
        if self.implementation == 'nnlan':
            self.init(['a', 'b'])
            for node in self.names:
                peer = (f'[[peers]]\nendpoint = "10.141.0.2:7331"\npublic_key = "{self.ids["b"]}"\n'
                        if node == 'a' else '')
                self.paths[node].write_text(f'name = "{node}"\nmax_neighbors = 1\n{peer}[tun]\nmtu = {self.args.mtu}\n')
                self.start(node)
                self.devices[node] = 'nnlan0'
            self.wait(lambda: all(self.rpc(n, 'status')['nodes'] == 2 for n in self.names), 'nnlan membership')
            self.wait(lambda: all((p := self.rpc(n, 'status')['neighbors'][0]['pmtu'])['udp_payload'] == p.get('maximum_udp_payload', 1232)
                                 for n in self.names), 'nnlan full path MTU')
            address = self.rpc('b', 'status')['address']
            self.hosts = {key: address[key] for key in ['ipv4', 'ipv6']}
        elif self.implementation.startswith('wireguard'):
            self.setup_wireguard()
            self.hosts = dict(ipv4='33.0.0.2', ipv6='fd33::2')
        else:
            self.devices = {n: 'wan' for n in self.names}
            self.hosts = dict(ipv4='10.141.0.2', ipv6='fd10:141::2')
        expected = {'nnlan': 'nnlan', 'wireguard-go': 'wireguard-go'}.get(self.implementation)
        for node in self.names:
            if expected:
                found = [int(p) for p in self.ip('netns', 'pids', self.names[node]).stdout.split()
                         if Path(f'/proc/{p}/comm').read_text().strip().startswith(expected)]
                assert len(found) == 1, (node, found)
                self.pids[node] = found[0]
        for family in ['ipv4', 'ipv6']:
            self.ns('a', 'ping', '-4' if family == 'ipv4' else '-6', '-n', '-c', '1', '-W', '3', self.hosts[family])
        self.spawn('b', ['iperf3', '-s'], self.directory / 'iperf-server.log')
        self.wait(lambda: '5201' in self.ns('b', 'ss', '-ln', '-t').stdout, 'iperf server')

    def setup_wireguard(self):
        keys = {}
        for node in self.names:
            private = self.command(['wg', 'genkey']).stdout
            public = subprocess.run(['wg', 'pubkey'], input=private, capture_output=True,
                                    text=True, check=True, timeout=10).stdout.strip()
            path = self.directory / f'{node}.key'
            # No keys in arguments, logs, reports, or world-readable files.
            with open(path, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as out:
                out.write(private)
            keys[node] = path, public
            device = f'{self.token}{node}'
            self.devices[node] = device
            if self.implementation == 'wireguard-go':
                uapi = Path('/var/run/wireguard') / f'{device}.sock'
                assert not uapi.exists(), 'fixture UAPI name already exists'
                self.uapi.append(uapi)
                self.spawn(node, ['wireguard-go', '-f', device], self.directory / f'{node}-wireguard-go.log')
                self.wait(lambda: self.ns(node, 'ip', 'link', 'show', 'dev', device, check=False).returncode == 0
                          and uapi.exists(), 'userspace WireGuard interface/UAPI')
            else:
                self.ns(node, 'ip', 'link', 'add', 'dev', device, 'type', 'wireguard')
        for index, node in enumerate(self.names, 1):
            other = 'b' if node == 'a' else 'a'
            peer_index = 2 if node == 'a' else 1
            device = self.devices[node]
            self.ns(node, 'wg', 'set', device, 'private-key', str(keys[node][0]), 'listen-port', '7331',
                    'peer', keys[other][1], 'allowed-ips', f'33.0.0.{peer_index}/32,fd33::{peer_index}/128',
                    'endpoint', f'10.141.0.{peer_index}:7331')
            self.ns(node, 'ip', 'address', 'add', f'33.0.0.{index}/32', 'dev', device)
            self.ns(node, 'ip', '-6', 'address', 'add', f'fd33::{index}/128', 'dev', device, 'nodad')
            self.ns(node, 'ip', 'link', 'set', 'dev', device, 'mtu', str(self.args.mtu), 'up')
            self.ns(node, 'ip', 'route', 'add', f'33.0.0.{peer_index}/32', 'dev', device)
            self.ns(node, 'ip', '-6', 'route', 'add', f'fd33::{peer_index}/128', 'dev', device)

    def state(self):
        result = {}
        for node, device in self.devices.items():
            state = dict(link=json.loads(self.ns(node, 'ip', '-s', '-j', 'link', 'show', 'dev', device).stdout),
                         qdisc=json.loads(self.ns(node, 'tc', '-s', '-j', 'qdisc', 'show', 'dev', 'wan').stdout))
            if self.implementation == 'nnlan':
                state['nnlan'] = self.rpc(node, 'status')
            elif self.implementation.startswith('wireguard'):
                # Do not use wg showconf/dump: both include private keys.
                state['wireguard'] = {field: self.ns(node, 'wg', 'show', device, field).stdout.strip()
                                      for field in ['latest-handshakes', 'transfer', 'endpoints']}
            if node in self.pids:
                state['process_start_ticks'] = Path(f'/proc/{self.pids[node]}/stat').read_text().rsplit(')', 1)[1].split()[19]
            result[node] = state
        return result

    def __exit__(self, kind, value, traceback):
        try:
            return super().__exit__(kind, value, traceback)
        finally:
            # Namespace teardown does not isolate the Unix socket filesystem.
            # Remove only names generated and reserved by this fixture.
            for path in self.uapi:
                self.command(self.root + ['rm', '-f', '--', str(path)])


def measure(net, args, case):
    host = net.hosts['ipv6' if case == 'ipv6' else 'ipv4']
    command = ['iperf3', '-c', host, '-J', '--get-server-output', '-C', args.congestion]
    if case.endswith('_reverse'):
        command.append('-R')
    warm = None
    if args.warmup:
        warm = json.loads(net.ns('a', *command, '-t', str(args.warmup), timeout=args.warmup + 20).stdout)
        assert 'error' not in warm, warm
    ping_log = net.directory / 'loaded-ping.log'
    ping = net.spawn('a', ['ping', '-6' if case == 'ipv6' else '-4', '-n', '-i', '0.02',
                           '-c', str(args.seconds * 50), '-W', '2', host], ping_log)
    before = net.state()
    cpu = {n: ticks(p) for n, p in net.pids.items()}
    host_before = host_cpu()
    start = time.monotonic()
    with LoadSampler(net, getattr(args, 'sample_ms', 0)) as sampler:
        trial = json.loads(net.ns('a', *command, '-t', str(args.seconds), timeout=args.seconds + 20).stdout)
    elapsed = time.monotonic() - start
    host_after = host_cpu()
    end_cpu = {n: ticks(p) for n, p in net.pids.items()}
    assert 'error' not in trial, trial
    after = net.state()
    for node in net.names:
        assert before[node]['link'][0]['ifindex'] == after[node]['link'][0]['ifindex']
        if node in net.pids:
            assert before[node]['process_start_ticks'] == after[node]['process_start_ticks']
        if net.implementation == 'nnlan':
            assert before[node]['nnlan']['boot_id'] == after[node]['nnlan']['boot_id']
            assert after[node]['nnlan']['neighbors'][0]['link']['repair'] == dict(fec=True, rtx=True)
    ping.wait(timeout=5)
    assert ping.returncode in [0, 1], ping_log.read_text()
    return dict(seconds=elapsed, receiver_mbps=trial['end']['sum_received']['bits_per_second'] / 1e6,
                daemon_cpu_percent={n: (end_cpu[n] - cpu[n]) / os.sysconf('SC_CLK_TCK') / elapsed * 100
                                    for n in net.pids} or None,
                host_cpu_percent=cpu_percent(host_before, host_after, elapsed),
                host_cpu_ticks_before=host_before, host_cpu_ticks_after=host_after,
                loaded_icmp=latency(ping_log.read_text()), before=before, after=after,
                warmup_iperf=warm, iperf=trial, load_samples=sampler.samples,
                daemon_logs={n: path.with_suffix('.log').read_text() for n, path in net.paths.items()}
                if net.implementation == 'nnlan' else {})


def summarize(results):
    summary = []
    for implementation, case in sorted({(r['implementation'], r['case']) for r in results}):
        rows = [r for r in results if (r['implementation'], r['case']) == (implementation, case)]
        summary.append(dict(implementation=implementation, case=case, trials=len(rows),
                            receiver_mbps=statistics.median(r['receiver_mbps'] for r in rows),
                            median_trial_rtt_p99_ms=statistics.median(r['loaded_icmp']['rtt_ms']['p99'] for r in rows
                                                                    if r['loaded_icmp']['samples'])
                            if any(r['loaded_icmp']['samples'] for r in rows) else None,
                            ping_replies=[r['loaded_icmp']['samples'] for r in rows],
                            tcp_retransmits=[r['iperf']['end']['sum_sent']['retransmits'] for r in rows],
                            daemon_cpu_percent={n: statistics.median(r['daemon_cpu_percent'][n] for r in rows)
                                                for n in rows[0]['daemon_cpu_percent']} if rows[0]['daemon_cpu_percent'] else None))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--implementations', nargs='+', choices=IMPLEMENTATIONS, default=list(IMPLEMENTATIONS))
    parser.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    parser.add_argument('--sample-ms', type=int, default=0, help='optional load-time status/queue sampling; 0 disables')
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--warmup', type=int, default=20)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--underlay-mbps', type=int, default=1000)
    parser.add_argument('--mtu', type=int, default=1280, help='common overlay MTU; WAN remains 1500')
    parser.add_argument('--congestion', choices=['bbr', 'cubic', 'reno'], default='bbr')
    parser.add_argument('--output', type=Path, default=Path('target/perf-comparison.json'))
    args = parser.parse_args()
    assert args.sample_ms == 0 or 100 <= args.sample_ms <= 5000
    assert 3 <= args.seconds <= 300 and 0 <= args.warmup <= 300 and 1 <= args.repeats <= 20
    assert 1 <= args.underlay_mbps <= 100_000 and 1280 <= args.mtu <= 1420
    assert len(set(args.implementations)) == len(args.implementations)
    assert len(set(args.cases)) == len(args.cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    provenance = dict(started_at=datetime.now(timezone.utc).isoformat(), kernel=platform.release(),
                      binary_sha256=digest(args.binary), fixture_sha256=digest(__file__),
                      sampler_sha256=digest(Path(__file__).with_name('load_sampler.py')),
                      helper_sha256=digest(Path(__file__).parents[1] / 'e2e/netns_fixture.py'),
                      measurement_helper_sha256=digest(Path(__file__).with_name('throughput.py')),
                      logical_cpus=os.cpu_count(), available_affinity=sorted(os.sched_getaffinity(0)),
                      cpu_model=next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                                     if line.startswith('model name')), loadavg=os.getloadavg(),
                      tools={name: tool_info(name, '--version') for name in ['wg', 'wireguard-go', 'iperf3', 'ethtool']},
                      arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()})
    report = dict(complete=False, provenance=provenance, results=[],
                  scope='same-host clean direct paths; fresh fixture per trial; stock worker/thread counts; no CPU pinning; one active TCP flow; 50 ICMP/s; common overlay MTU; nnlan default FEC+RTX and encryption mode recorded in daemon status; no FEC in WireGuard; not a feature-equivalent comparison',
                  cpu_scope='daemon CPU: 100%=one logical core, null for kernel/underlay, not zero cost; whole-host CPU includes unrelated tasks and is NOT attributable to a backend')
    save(args.output, report)
    try:
        for repeat, implementation, case in schedule(args.implementations, args.cases, args.repeats):
            with Fixture(args, implementation) as net:
                net.setup()
                setup = {n: dict(wan_offloads=net.ns(n, 'ethtool', '-k', 'wan').stdout,
                                 overlay_offloads=net.ns(n, 'ethtool', '-k', net.devices[n]).stdout,
                                 tcp_congestion=net.ns(n, 'sysctl', '-n', 'net.ipv4.tcp_congestion_control').stdout.strip())
                         for n in net.names}
                result = dict(repeat=repeat, implementation=implementation, case=case, setup=setup,
                              namespace_prefix=net.token, **measure(net, args, case))
            # Publish only after this trial's daemons, namespaces and UAPI sockets are gone.
            result['cleanup_complete'] = True
            report['results'].append(result)
            report['summary'] = summarize(report['results'])
            save(args.output, report)
            print(json.dumps({k: result[k] for k in ['implementation', 'case', 'repeat', 'receiver_mbps', 'daemon_cpu_percent']}
                             | dict(rtt_ms=result['loaded_icmp']['rtt_ms'])), flush=True)
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        save(args.output, report)
        raise
    report['complete'] = True
    provenance['finished_at'] = datetime.now(timezone.utc).isoformat()
    save(args.output, report)


if __name__ == '__main__':
    main()
