import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import unittest

from deepsick_attack.config import load_policy
from deepsick_attack.verifiers import (
    anti_false_completion,
    evidence_check,
    exploit_provenance,
    flag_detector,
    reproduce_check,
    scope_guard,
    stage_detector,
)

FLAG = "flag{DEMO_ONLY_NOT_A_REAL_FLAG}"


def good_state():
    return {
        "trace": [
            {"stage": "exploit", "action": "a", "evidence_paths": ["e1"], "verdicts": []},
            {"stage": "flag", "action": "b", "evidence_paths": ["e2"],
             "verdicts": [{"name": "flag_detector", "detail": f"工具输出命中 {FLAG}"}]},
            {"stage": "flag", "action": "b:replay", "evidence_paths": ["e3"],
             "verdicts": [{"name": "flag_detector", "detail": f"工具输出命中 {FLAG}"}]},
        ],
        "facts": [{"confidence": "observed", "evidence_paths": ["e2"]}],
        "intents": [{"status": "done"}],
    }


class VerifierTest(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()

    def test_flag_detector_rejects_model_text(self):
        value, verdict = flag_detector(f"模型声称 {FLAG}", "model_text", self.policy)
        self.assertIsNone(value)
        self.assertTrue(verdict.passed)

    def test_flag_detector_accepts_tool_output(self):
        value, _ = flag_detector(f"output {FLAG}", "tool_output", self.policy)
        self.assertEqual(value, FLAG)

    def test_scope_guard(self):
        allowed = self.policy["scope_allowlist"][0]
        self.assertTrue(scope_guard(allowed, self.policy).passed)
        self.assertFalse(scope_guard("198.51.100.1", self.policy).passed)

    def test_stage_detector(self):
        self.assertTrue(stage_detector("recon", self.policy).passed)
        self.assertFalse(stage_detector("unknown", self.policy).passed)

    def test_exploit_provenance(self):
        self.assertTrue(exploit_provenance(good_state(), self.policy).passed)
        state = good_state()
        state["trace"] = state["trace"][1:]
        self.assertFalse(exploit_provenance(state, self.policy).passed)

    def test_reproduce_check_requires_two_distinct_actions(self):
        self.assertTrue(reproduce_check(good_state(), FLAG).passed)
        state = good_state()
        state["trace"] = state["trace"][:2]
        self.assertFalse(reproduce_check(state, FLAG).passed)

    def test_evidence_check(self):
        self.assertTrue(evidence_check(good_state()).passed)
        state = good_state()
        state["trace"][0]["evidence_paths"] = []
        self.assertFalse(evidence_check(state).passed)

    def test_anti_false_completion_all_pass(self):
        ok, checks = anti_false_completion(good_state(), self.policy, FLAG)
        self.assertTrue(ok)
        self.assertEqual(len(checks), 6)

    def test_anti_false_completion_blocks_false_claim(self):
        state = good_state()
        state["intents"] = [{"status": "running"}]
        ok, checks = anti_false_completion(state, self.policy, FLAG)
        self.assertFalse(ok)
        self.assertFalse(next(c for c in checks if "封锁" in c["item"])["passed"])


if __name__ == "__main__":
    unittest.main()
