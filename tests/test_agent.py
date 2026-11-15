import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import tempfile
import unittest

from deepsick_attack.agent import run_target, self_test
from deepsick_attack.config import load_policy, stage_ids
from deepsick_attack.events import set_sink


class AgentE2ETest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.workspace = self.tmp.name + "/workspace"
        self.policy = load_policy()
        self.events = []
        set_sink(self.events.append)
        self.addCleanup(set_sink, None)

    def test_normal_run_scores_full_marks(self):
        result = run_target(1, self.policy, self.workspace, max_steps=24)
        self.assertTrue(result["proved"])
        self.assertEqual(result["path_points"], 40.0)
        self.assertEqual(result["total_points"], 240.0)
        self.assertEqual(result["steps"], 7)
        self.assertEqual(len(result["checks"]), 6)
        self.assertTrue(all(c["passed"] for c in result["checks"]))

    def test_failure_recovers_inside_stage_without_skipping(self):
        result = run_target(
            2, self.policy, self.workspace, max_steps=24,
            inject_failure="fingerprint",
        )
        self.assertTrue(result["proved"])
        self.assertEqual(result["total_points"], 240.0)
        self.assertEqual(result["steps"], 8)

        entered = [e["stage"] for e in self.events
                   if e["event"] == "stage_enter"]
        self.assertEqual(entered, stage_ids(self.policy))

        fingerprint_actions = [e["action"] for e in self.events
                               if e["event"] == "attempt"
                               and e["stage"] == "fingerprint"]
        self.assertIn("probe:fingerprint:alt-path", fingerprint_actions)
        self.assertTrue(any(e["stage_exit"] is False for e in self.events
                            if e["event"] == "attempt"
                            and e["stage"] == "fingerprint"))

    def test_self_test_reports_both_paths(self):
        summary = self_test(self.policy, self.workspace)
        self.assertTrue(summary["normal"]["proved"])
        self.assertTrue(summary["with_failure"]["proved"])
        self.assertEqual(summary["normal"]["total_points"], 240.0)
        self.assertEqual(summary["with_failure"]["total_points"], 240.0)


if __name__ == "__main__":
    unittest.main()
