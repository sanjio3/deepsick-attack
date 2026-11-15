import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import unittest

from deepsick_attack.config import load_policy, stage_ids
from deepsick_attack.path_score import PathMatcher
from deepsick_attack.stage_runner import StageRunner


def passed_step(stage):
    return {"stage": stage, "verdicts": [{"name": "stage_exit", "passed": True}]}


class StageRunnerTest(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()
        self.runner = StageRunner(self.policy)
        self.matcher = PathMatcher(stage_ids(self.policy), 40.0,
                                   self.policy["score_weights"],
                                   self.policy["path_formula"])

    def test_current_starts_at_first_stage(self):
        self.assertEqual(self.runner.current([])["id"], "recon")

    def test_current_skips_only_passed_stages(self):
        trace = [passed_step("recon"), passed_step("fingerprint")]
        self.assertEqual(self.runner.current(trace)["id"], "vuln")

    def test_current_returns_none_when_all_passed(self):
        trace = [passed_step(s) for s in self.runner.ids]
        self.assertIsNone(self.runner.current(trace))

    def test_contains_any_detector(self):
        stage = self.runner.path[0]
        ok = self.runner.check_exit(stage, "open ports: 80, 8080", "tool_output")
        self.assertTrue(ok.passed)
        bad = self.runner.check_exit(stage, "connection refused", "tool_output")
        self.assertFalse(bad.passed)

    def test_flag_detector(self):
        stage = next(s for s in self.runner.path if s["id"] == "flag")
        ok = self.runner.check_exit(stage, "flag{DEMO}", "tool_output")
        self.assertTrue(ok.passed)
        bad = self.runner.check_exit(stage, "nothing here", "tool_output")
        self.assertFalse(bad.passed)

    def test_rejects_non_tool_output(self):
        stage = self.runner.path[0]
        verdict = self.runner.check_exit(stage, "open ports: 80", "model_text")
        self.assertFalse(verdict.passed)

    def test_next_action_stays_inside_stage(self):
        stage = self.runner.path[0]
        self.assertEqual(self.runner.next_action(stage, 0), stage["action"])
        self.assertEqual(self.runner.next_action(stage, 1), stage["fallbacks"][0])
        self.assertEqual(self.runner.next_action(stage, 2), stage["fallbacks"][1])
        self.assertIsNone(self.runner.next_action(stage, 3))

    def test_deviation_reports_missing_stages(self):
        deviation = self.runner.deviation(["recon", "flag"], self.matcher)
        self.assertEqual(deviation["points"], 8.0)
        self.assertIn("exploit", deviation["missing"])


if __name__ == "__main__":
    unittest.main()
