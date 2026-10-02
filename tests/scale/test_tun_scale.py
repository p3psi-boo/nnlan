import unittest
from types import SimpleNamespace
from tun_scale import components, edge_addresses, neighbors, ping_command, require_ping, state_errors, traffic_pairs, underlay_neighbors
from daemon_scale import tree_path


class TunScaleFixture(unittest.TestCase):
    def test_ping_limits_sends_without_deadline_and_keeps_full_ip_mtu(self):
        for family, address, size in [('4', '33.0.0.1', '1252'), ('6', 'fd33::1', '1232')]:
            command = ping_command(family, address)
            self.assertNotIn('-w', command)
            for option, value in [('-c', '3'), ('-i', '0.1'), ('-W', '2'), ('-M', 'do'), ('-s', size)]:
                self.assertEqual(command[command.index(option) + 1], value)
            self.assertEqual(command[-1], address)

    def test_underlay_neighbors_are_reciprocal_and_use_remote_macs(self):
        count = 1000
        macs = [{'up': f'{n}:up', **{f'u{c}': f'{n}:u{c}' for c in neighbors(count, n) if c > n}}
                for n in range(count)]
        all_ips = [a for child in range(1, count) for a in edge_addresses(child)]
        self.assertEqual(len(set(all_ips)), 1998)
        plans = [underlay_neighbors(count, n, macs) for n in range(count)]
        self.assertEqual(sum(map(len, plans)), 1998)
        for child in range(1, count):
            parent = (child - 1) // 3
            a, b = edge_addresses(child)
            self.assertIn(dict(dst=b, dev=f'u{child}', lladdr=macs[child]['up']), plans[parent])
            self.assertIn(dict(dst=a, dev='up', lladdr=macs[parent][f'u{child}']), plans[child])

    def test_partitions_and_pairs_cover_every_node_without_crossing_cut(self):
        for count in [7, 13, 100, 1000]:
            groups = components(count, True)
            self.assertEqual(sorted(n for g in groups for n in g), list(range(count)))
            self.assertNotEqual(0 in groups[0], 1 in groups[0])
            self.assertEqual(len(traffic_pairs(groups)), count)
            for a, b in traffic_pairs(groups):
                self.assertNotEqual(a, b)
                path = tree_path(a, b)
                self.assertFalse(any({x, y} == {0, 1} for x, y in zip(path, path[1:])))
            self.assertEqual(sum(len(neighbors(count, n)) for n in range(count)), 2 * (count - 1))

    def test_loss_or_short_probe_output_never_passes(self):
        def ping(code, text): return require_ping(SimpleNamespace(returncode=code, stdout=text), 3)
        self.assertTrue(ping(0, '3 packets transmitted, 3 received, 0% packet loss'))
        self.assertFalse(ping(0, '3 packets transmitted, 2 received, 33% packet loss'))
        self.assertFalse(ping(0, '6 packets transmitted, 3 received, 50% packet loss'))
        self.assertFalse(ping(0, '3 packets transmitted, 0 received, 100% packet loss'))
        self.assertFalse(ping(0, '0% packet loss'))
        self.assertFalse(ping(1, '3 packets transmitted, 3 received, 0% packet loss'))

    def test_component_counts_unique_addresses_and_exact_adjacency_are_required(self):
        ids = list(map(str, range(7)))
        groups = components(7, True)
        states = {}
        for group in groups:
            for n in group:
                states[n] = dict(nodes=len(group), addresses_claimed=True, tun_enabled=True, relay=True, kernel_routes_ready=True,
                    address=dict(ipv4=f'33.0.0.{n+1}', ipv6=f'fd33::{n+1}'), neighbors=[dict(node=ids[x]) for x in neighbors(7, n) if x in group])
        self.assertEqual(state_errors(states, ids, groups), [])
        states[0]['kernel_routes_ready'] = False
        self.assertTrue(state_errors(states, ids, groups), 'userspace membership alone is not kernel readiness')
        states[0]['kernel_routes_ready'] = True
        states[0]['address']['ipv4'] = states[1]['address']['ipv4']
        self.assertEqual(state_errors(states, ids, groups), [], 'same address in separate components is legitimate')
        states[2]['address']['ipv4'] = states[0]['address']['ipv4']
        self.assertTrue(state_errors(states, ids, groups))
        states[2]['address']['ipv4'] = '33.0.0.3'
        states[0]['neighbors'].append(dict(node='1'))
        self.assertTrue(state_errors(states, ids, groups))
