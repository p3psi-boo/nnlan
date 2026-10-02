#!/usr/bin/env python3
"""Real namespace/TUN tree: collision merge, partition, recovery and restart.

No host routes, bridge, forwarding or firewall rules are installed. Each tree
edge is a point-to-point underlay; overlay packets must traverse actual relays.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import re
import sys
import time

from daemon_scale import tree_path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'e2e'))
from netns_fixture import Network


def components(count, split):
    groups = [[], []] if split else [[]]
    for node in range(count):
        ancestor = node
        while ancestor > 1:
            ancestor = (ancestor - 1) // 3
        groups[int(ancestor == 1) if split else 0].append(node)
    return groups


def neighbors(count, node):
    return ([((node - 1) // 3)] if node else []) + list(range(node * 3 + 1, min(count, node * 3 + 4)))


def edge_addresses(child):
    return tuple(f'10.112.{child // 64}.{(child % 64) * 4 + host}' for host in [1, 2])


def underlay_neighbors(count, node, macs):
    entries = []
    for peer in neighbors(count, node):
        child = max(node, peer)
        parent_ip, child_ip = edge_addresses(child)
        parent_side = node < peer
        entries.append(dict(dst=child_ip if parent_side else parent_ip,
                            dev=f'u{child}' if parent_side else 'up',
                            lladdr=macs[peer]['up' if parent_side else f'u{child}']))
    return entries


def install_underlay_neighbors(net, names, workers):
    # Point-to-point lab links have known peers. Keep their ARP entries out of
    # the shared dynamic-neighbor GC budget without changing host sysctls.
    def addresses(name):
        links = json.loads(net.ip('-n', net.names[name], '-j', 'link', 'show').stdout)
        return {link['ifname']: link['address'] for link in links}

    macs = list(workers.map(addresses, names))

    def install(node):
        entries = underlay_neighbors(len(names), node, macs)
        for entry in entries:
            net.ip('-n', net.names[names[node]], 'neigh', 'add', entry['dst'],
                   'lladdr', entry['lladdr'], 'nud', 'permanent', 'dev', entry['dev'])
        actual = json.loads(net.ip('-n', net.names[names[node]], '-4', '-j', 'neigh', 'show').stdout)
        key = lambda e: (e['dst'], e['dev'], e['lladdr'])
        assert sorted(map(key, actual)) == sorted(map(key, entries)), (node, actual, entries)
        assert all(e['state'] == ['PERMANENT'] for e in actual), (node, actual)
        return dict(node=node, entries=actual)

    return list(workers.map(install, range(len(names))))


def traffic_pairs(groups):
    return [(source, group[(index + len(group) // 2) % len(group)])
            for group in groups for index, source in enumerate(group)]


def require_ping(result, count):
    match = re.search(r'(\d+) packets transmitted, (\d+) received', result.stdout)
    return result.returncode == 0 and match is not None and tuple(map(int, match.groups())) == (count, count)


def ping_command(family, address):
    # iputils -c with -w caps replies, not transmissions. Stop after exactly
    # three sends; the caller bounds the entire process separately.
    payload = {'4': '1252', '6': '1232'}[family]
    return ['ping', '-' + family, '-n', '-M', 'do', '-c', '3', '-i', '0.1',
            '-W', '2', '-s', payload, address]


def state_errors(states, ids, groups):
    errors = []
    count = len(ids)
    for group in groups:
        members = set(group)
        for family in ['ipv4', 'ipv6']:
            addresses = [states.get(n, {}).get('address', {}).get(family) for n in group]
            pool = ipaddress.ip_network('33.0.0.0/8' if family == 'ipv4' else 'fd33::/16')
            try:
                valid = all(ipaddress.ip_address(a) in pool for a in addresses)
            except ValueError:
                valid = False
            if not valid or len(set(addresses)) != len(group):
                errors.append(f'{family} claims not unique in component rooted at {group[0]}')
        for n in group:
            state = states.get(n, {})
            actual = {p['node'] for p in state.get('neighbors', [])}
            expected = {ids[x] for x in neighbors(count, n) if x in members}
            if (state.get('nodes') != len(group) or not state.get('addresses_claimed')
                    or not state.get('tun_enabled') or not state.get('relay') or actual != expected
                    or not state.get('kernel_routes_ready')
                    or len(state.get('neighbors', [])) != len(expected)):
                errors.append(f'node {n}: members={state.get("nodes")}, neighbors={len(actual)}, expected={len(expected)}, kernel_routes_ready={state.get("kernel_routes_ready")}')
    return errors


class TunNetwork(Network):
    def __exit__(self, kind, value, traceback):
        try:
            return super().__exit__(kind, value, traceback)
        finally:
            self.report['all_owned_processes_reaped'] = all(p.poll() is not None for p in self.processes)
            try:
                remaining = {line.split()[0] for line in self.ip('netns', 'list').stdout.splitlines() if line.strip()}
                self.report['all_owned_namespaces_removed'] = not (remaining & set(self.names.values()))
            except Exception as error:
                self.report['cleanup_observation_error'] = repr(error)

    def failure_evidence(self, value):
        # Keep scale failures bounded and available in the per-run report; the
        # shared base fixture still owns all process/namespace cleanup.
        self.report['failure_logs'] = {
            name: self.paths[name].with_suffix('.log').read_text()[-4096:]
            for name in self.paths if self.paths[name].with_suffix('.log').exists()
        }


def run(args, report, save):
    count = args.nodes
    names = [f'n{n}' for n in range(count)]
    net = TunNetwork(args.binary, names)
    net.report = report
    with net, ThreadPoolExecutor(max_workers=16) as workers:
        report['namespace_prefix'] = net.token
        report['setup_stage'] = 'identities'
        save()
        net.init(names)
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'fixtures/ipv4-collision.json').read_text())
        for n, field in [(0, 'seed_a'), (1, 'seed_b')]:
            net.paths[names[n]].with_name('identity.key').write_bytes(b'GGBKEY1\n' + bytes.fromhex(fixture[field]))
            net.ids[names[n]] = net.cli(names[n], 'identity').stdout.strip()
        ids = [net.ids[name] for name in names]
        report['ids'] = ids
        endpoints = [[] for _ in names]
        parent_endpoints = {}
        report['setup_stage'] = 'links'
        for child in range(1, count):
            parent = (child - 1) // 3
            a, b = edge_addresses(child)
            net.link(names[parent], names[child], f'u{child}', 'up', [a + '/30', b + '/30'])
            endpoints[parent].append(a + ':7331')
            endpoints[child].append(b + ':7331')
            parent_endpoints[child] = a + ':7331'
            if child % 50 == 0 or child == count - 1:
                report['setup_links'] = child
                save()
        report['setup_stage'] = 'permanent_neighbors'
        save()
        report['underlay'] = dict(mode='permanent_ipv4_neighbors',
                                  nodes=install_underlay_neighbors(net, names, workers))
        report['setup_stage'] = 'daemons'
        save()
        # Independent initial address allocations, then a real collision merge.
        net.ip('-n', net.names['n1'], 'link', 'set', 'dev', 'up', 'down')
        for n, name in enumerate(names):
            config = (f'name = "{name}"\nlisten = "0.0.0.0:7331"\n'
                      f'max_neighbors = {len(neighbors(count, n))}\nendpoints = {json.dumps(endpoints[n])}\n')
            if n:
                config += (f'\n[[peers]]\nendpoint = "{parent_endpoints[n]}"\n'
                           f'public_key = "{ids[(n - 1) // 3]}"\n')
            config += '\n[tun]\nname = "nnlan0"\nenabled = true\nmtu = 1280\n'
            net.paths[name].write_text(config)
            net.start(name)
        report['setup_finished_at'] = datetime.now(timezone.utc).isoformat()
        report['setup_stage'] = 'complete'
        save()

        def converge(label, groups):
            start = time.monotonic()
            observation = report.setdefault('convergence', {})[label] = {}
            while True:
                def status(n):
                    try:
                        return n, net.rpc(names[n], 'status'), None
                    except Exception as error:
                        return n, {}, repr(error)
                outcomes = list(workers.map(status, range(count)))
                states = {n: state for n, state, error in outcomes}
                errors = state_errors(states, ids, groups)
                errors.extend(f'{n}: {error}' for n, state, error in outcomes if error)
                observation.update(seconds=time.monotonic() - start, errors=errors,
                                   states=states, component_sizes=list(map(len, groups)))
                save()
                assert all(child.poll() is None for child in net.daemons.values()), 'daemon exited'
                assert time.monotonic() - start < args.convergence_timeout, f'{label}: {errors[:8]}'
                if not errors:
                    def tun_addresses(n):
                        result = json.loads(net.ns(names[n], 'ip', '-j', 'address', 'show', 'dev', 'nnlan0').stdout)
                        locals = {a['local'] for a in result[0]['addr_info']}
                        assert all(states[n]['address'][f] in locals for f in ['ipv4', 'ipv6']), (n, result)
                        return dict(node=n, addresses=result)
                    observation['kernel_tun_addresses'] = list(workers.map(tun_addresses, range(count)))
                    observation['seconds'] = time.monotonic() - start
                    save()
                    assert observation['seconds'] < args.convergence_timeout, f'{label}: kernel address verification timed out'
                    return states
                time.sleep(.5)

        def traffic(label, groups, states):
            start = time.monotonic()
            outcomes = report.setdefault('traffic', {})[label] = []

            def exchange(pair):
                source, destination = pair
                result = dict(source=source, destination=destination, ok=False, ping={})
                try:
                    for family in ['4', '6']:
                        address = states[destination]['address'][f'ipv{family}']
                        command = net.ns(names[source], *ping_command(family, address),
                                         timeout=5, check=False)
                        result['ping'][family] = dict(exit_code=command.returncode, raw=command.stdout,
                                                       stderr=command.stderr, ok=require_ping(command, 3))
                    trace = net.rpc(names[source], 'trace', names[destination])
                    result['trace'] = trace
                    expected = tree_path(source, destination)[1:]
                    result['expected_path'] = expected
                    result['ok'] = (all(x['ok'] for x in result['ping'].values()) and trace['complete']
                                    and [h.get('node') for h in trace['hops']] == [ids[n] for n in expected])
                except Exception as error:
                    result['error'] = repr(error)
                return result

            for future in as_completed([workers.submit(exchange, pair) for pair in traffic_pairs(groups)]):
                outcomes.append(future.result())
                if not outcomes[-1]['ok'] or len(outcomes) % 16 == 0:
                    save()
            outcomes.sort(key=lambda r: r['source'])
            report.setdefault('traffic_seconds', {})[label] = time.monotonic() - start
            save()
            failed = [r for r in outcomes if not r['ok']]
            assert not failed, f'{label}: {len(failed)}/{count} exchanges failed; first={failed[:1]}'

        split = components(count, True)
        initial = converge('initial_partitions', split)
        report['initial_collision'] = [initial[n]['address'] for n in [0, 1]]
        assert all(initial[n]['address']['ipv4'] == fixture['ipv4'] and initial[n]['address']['probe'] == 0 for n in [0, 1])
        traffic('initial_partitions', split, initial)
        net.ip('-n', net.names['n1'], 'link', 'set', 'dev', 'up', 'up')
        whole = components(count, False)
        merged = converge('collision_merge', whole)
        assert merged[0]['address']['ipv4'] != merged[1]['address']['ipv4']
        loser, = [n for n in [0, 1] if merged[n]['address']['probe'] > 0]
        report['collision_loser'] = loser
        assert all(initial[n]['address']['ipv6'] == merged[n]['address']['ipv6'] for n in range(count))
        for n in [0, 1]:
            addresses = json.loads(net.ns(names[n], 'ip', '-j', 'address', 'show', 'dev', 'nnlan0').stdout)[0]['addr_info']
            assert merged[n]['address']['ipv4'] in [a['local'] for a in addresses]
        traffic('collision_merge', whole, merged)
        net.ip('-n', net.names['n1'], 'link', 'set', 'dev', 'up', 'down')
        partitioned = converge('partition', split)
        report['partition_probes'] = []
        for source, destination in [(0, 1), (1, 0)]:
            for family in ['4', '6']:
                result = net.ns(names[source], 'ping', '-' + family, '-n', '-c', '1', '-W', '1', '-w', '2',
                                merged[destination]['address'][f'ipv{family}'], check=False)
                report['partition_probes'].append(dict(source=source, destination=destination, family=family,
                                                       exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
                assert result.returncode != 0, 'partition unexpectedly forwarded IP traffic'
        traffic('partition', split, partitioned)
        net.ip('-n', net.names['n1'], 'link', 'set', 'dev', 'up', 'up')
        restored = converge('rejoin', whole)
        assert all(restored[n]['address'] == merged[n]['address'] for n in range(count))
        traffic('rejoin', whole, restored)
        previous_boot = {n: restored[n]['boot_id'] for n in range(count)}
        net.crash(names[loser])
        net.start(names[loser])
        restarted = converge('restart_collision_loser', whole)
        assert restarted[loser]['boot_id'] != previous_boot[loser]
        assert all(restarted[n]['boot_id'] == previous_boot[n] for n in range(count) if n != loser)
        assert all(restarted[n]['address'] == merged[n]['address'] for n in range(count))
        persisted = json.loads(net.command(net.root + ['cat', str(net.paths[names[loser]].with_name('identity.state.json'))]).stdout)
        assert persisted['probe'] == merged[loser]['address']['probe']
        report['persisted_collision_state'] = persisted
        traffic('restart_collision_loser', whole, restarted)
    assert report['all_owned_processes_reaped'] and report['all_owned_namespaces_removed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/nnlan'))
    parser.add_argument('--nodes', type=int, default=100)
    parser.add_argument('--convergence-timeout', type=float, default=180)
    parser.add_argument('--output', type=Path, default=Path('target/tun-scale.json'))
    args = parser.parse_args()
    assert 7 <= args.nodes <= 1000 and args.convergence_timeout > 0
    here = Path(__file__).resolve()
    files = [here, here.with_name('daemon_scale.py'), here.parents[1] / 'e2e/netns_fixture.py',
             here.parents[1] / 'fixtures/ipv4-collision.json']
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    report = dict(ok=False, nodes=args.nodes, tun_enabled=True, workers=16,
                  convergence_timeout_seconds=args.convergence_timeout,
                  scope='real isolated namespaces/TUN, sparse tree, collision merge, partition/rejoin and one relay restart; not throughput or long churn acceptance',
                  provenance=dict(binary_sha256=digest(args.binary), fixture_sha256={str(p.relative_to(here.parents[2])): digest(p) for p in files},
                                  kernel=platform.release(), started_at=datetime.now(timezone.utc).isoformat()))
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        tmp = args.output.with_suffix('.tmp')
        tmp.write_text(json.dumps(report, indent=2) + '\n')
        tmp.replace(args.output)

    save()
    try:
        run(args, report, save)
        report['ok'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        report['provenance']['finished_at'] = datetime.now(timezone.utc).isoformat()
        save()


if __name__ == '__main__':
    main()
