import unittest
from concurrent.futures import ThreadPoolExecutor
from daemon_scale import exchange_batch, tree_path


class ScaleDiagnostics(unittest.TestCase):
    def test_tree_paths_include_endpoints_and_preserve_exact_hops(self):
        self.assertEqual(tree_path(0, 5), [0, 1, 5])
        self.assertEqual(tree_path(5, 0), [5, 1, 0])
        self.assertEqual(tree_path(5, 8), [5, 1, 0, 2, 8])
        for source in range(1000):
            destination = (source + 500) % 1000
            path = tree_path(source, destination)
            self.assertEqual(path[0], source)
            self.assertEqual(path[-1], destination)
            self.assertEqual(len(path), len(set(path)))
            self.assertLessEqual(len(set(path) | {0, 1, 2, 3}), 16)
            for a, b in zip(path, path[1:]):
                self.assertTrue(a == (b-1)//3 or b == (a-1)//3)

    def run_batch(self, failed, broken_snapshot=False):
        report, checkpoints, snapshots = {}, [], []
        def ping(index):
            return dict(source=index, destination=index+100, ok=index not in failed,
                        error="injected timeout" if index in failed else None)
        def checkpoint():
            checkpoints.append(len(report["exchanges"]))
        def snapshot(outcome):
            snapshots.append(outcome)
            if broken_snapshot:
                raise OSError("status unavailable")
            return dict(failed_exchange=outcome)
        with ThreadPoolExecutor(max_workers=16) as workers:
            if failed:
                with self.assertRaisesRegex(RuntimeError, f"{len(failed)}/100 exchanges failed"):
                    exchange_batch(workers, 100, ping, report, "exchanges", checkpoint, snapshot)
            else:
                exchange_batch(workers, 100, ping, report, "exchanges", checkpoint, snapshot)
        self.assertEqual([row["source"] for row in report["exchanges"]], list(range(100)))
        self.assertEqual({row["source"] for row in report["exchanges"] if not row["ok"]}, failed)
        self.assertEqual(checkpoints[-1], 100)
        self.assertEqual(len(snapshots), bool(failed))
        return report

    def test_success_never_runs_failure_snapshot(self):
        self.assertNotIn("failure_snapshots", self.run_batch(set()))

    def test_one_timeout_does_not_erase_other_outcomes_or_pass_gate(self):
        self.run_batch({3, 77})

    def test_diagnostic_failure_never_erases_original_exchange_failure(self):
        report = self.run_batch({3}, broken_snapshot=True)
        self.assertIn("status unavailable", report["failure_snapshots"]["exchanges"]["snapshot_error"])


if __name__ == "__main__":
    unittest.main()
