import os
import unittest

from compare import cpu_percent, schedule, summarize


class ComparisonTests(unittest.TestCase):
    def test_schedule_rotates_without_omitting_or_repeating_trials(self):
        implementations = ['underlay', 'nnlan', 'wireguard-kernel', 'wireguard-go']
        cases = ['ipv4', 'ipv6', 'ipv4_reverse']
        plan = list(schedule(implementations, cases, 3))
        self.assertEqual(len(plan), 36)
        self.assertEqual(set(plan), {(r, i, c) for r in range(3) for i in implementations for c in cases})
        self.assertEqual([plan[r * 12][1] for r in range(3)], implementations[:3])
        self.assertEqual([plan[r * 12][2] for r in range(3)], cases)

    def test_cpu_counts_work_not_idle_iowait_or_steal(self):
        hz = os.sysconf('SC_CLK_TCK')
        self.assertEqual(cpu_percent([0] * 8, [hz, 0, hz, hz * 50, hz * 30, 0, 0, hz], 2), 100)

    def row(self, implementation, throughput, samples=750):
        return dict(implementation=implementation, case='ipv4', receiver_mbps=throughput,
                    daemon_cpu_percent=None if implementation == 'wireguard-kernel' else dict(a=75, b=70),
                    loaded_icmp=dict(samples=samples, rtt_ms=dict(p99=10 if samples else None)),
                    iperf=dict(end=dict(sum_sent=dict(retransmits=0))))

    def test_summary_keeps_kernel_cpu_unknown_and_uses_median(self):
        rows = [self.row('wireguard-kernel', value) for value in [900, 100, 800]]
        rows += [self.row('nnlan', value) for value in [200, 280, 285]]
        summary = {r['implementation']: r for r in summarize(rows)}
        self.assertIsNone(summary['wireguard-kernel']['daemon_cpu_percent'])
        self.assertEqual(summary['wireguard-kernel']['receiver_mbps'], 800)
        self.assertEqual(summary['nnlan']['receiver_mbps'], 280)
        self.assertEqual(summary['nnlan']['daemon_cpu_percent'], dict(a=75, b=70))

    def test_summary_records_all_ping_loss_instead_of_inventing_latency(self):
        result = summarize([self.row('nnlan', 0, samples=0)])[0]
        self.assertEqual(result['ping_replies'], [0])
        self.assertIsNone(result['median_trial_rtt_p99_ms'])


class LossBoundaryTests(unittest.TestCase):
    def test_aggregates_or_missing_counter_invalidate_the_comparison(self):
        from compare_loss import check_packet_boundary
        check_packet_boundary({'nftables': [{'counter': {'packets': 0}}]})
        for entries in [[], [{'counter': {'packets': 1}}],
                        [{'counter': {'packets': 0}}, {'counter': {'packets': 0}}]]:
            with self.assertRaises(AssertionError):
                check_packet_boundary({'nftables': entries})


class LoadSamplerTests(unittest.TestCase):
    def test_disabled_sampler_does_not_touch_network(self):
        from load_sampler import LoadSampler
        with LoadSampler(None, 0) as sampler:
            pass
        self.assertEqual(sampler.samples, [])

    def test_failed_observation_invalidates_measurement(self):
        from load_sampler import LoadSampler
        class Broken:
            names = {'a': 'fixture'}
            def ns(self, *args):
                raise RuntimeError('fixture sample failed')
        with self.assertRaisesRegex(RuntimeError, 'fixture sample failed'):
            with LoadSampler(Broken(), 100) as sampler:
                sampler.thread.join(timeout=1)


if __name__ == '__main__':
    unittest.main()
