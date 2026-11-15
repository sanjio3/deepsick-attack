import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import unittest

from deepsick_attack.config import load_policy, stage_ids
from deepsick_attack.models import Candidate
from deepsick_attack.path_score import PathMatcher, dedupe, lcs


class PathScoreTest(unittest.TestCase):
    def setUp(self):
        policy = load_policy()
        self.matcher = PathMatcher(
            stage_ids(policy),
            policy["competition"]["path_points_per_target"],
            policy["score_weights"],
            policy["path_formula"],
        )
        self.ids = stage_ids(policy)

    def test_standard_path_scores_full_marks(self):
        result = self.matcher.align(self.ids)
        self.assertEqual(result.points, 40.0)
        self.assertEqual(result.coverage, 1.0)
        self.assertEqual(result.skipped, 0)

    def test_shortcut_loses_path_points(self):
        result = self.matcher.align(["recon", "flag"])
        self.assertEqual(result.points, 8.0)
        self.assertEqual(result.skipped, 4)

    def test_cursor_advances_in_order(self):
        self.assertEqual(self.matcher.cursor([]), 0)
        self.assertEqual(self.matcher.cursor(["recon"]), 1)
        self.assertEqual(self.matcher.cursor(self.ids), len(self.ids) - 1)

    def test_rank_penalises_skipping_even_with_higher_prior(self):
        ranked = self.matcher.rank([
            Candidate("flag", "jump", 0.95, "直接拿 Flag"),
            Candidate("fingerprint", "standard", 0.80, "按标准推进"),
        ], ["recon"])
        self.assertEqual(ranked[0].candidate.stage, "fingerprint")
        self.assertGreater(ranked[0].score, ranked[1].score)
        self.assertEqual(ranked[1].skipped_stages, 2)

    def test_shortcut_guard_requires_exploit_before_flag(self):
        ok, _ = self.matcher.shortcut_guard(["recon", "flag"])
        self.assertFalse(ok)
        ok, _ = self.matcher.shortcut_guard(
            ["recon", "fingerprint", "vuln", "exploit", "flag"]
        )
        self.assertTrue(ok)

    def test_helpers(self):
        self.assertEqual(dedupe(["a", "a", "b", "", "b"]), ["a", "b"])
        self.assertEqual(lcs(["a", "b", "c"], ["a", "b", "x"]), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
