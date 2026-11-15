import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import copy
import json
import tempfile
import unittest
from pathlib import Path

from deepsick_attack.config import ConfigError, load_policy, stage_ids, validate_policy


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy()

    def test_default_template_is_valid(self):
        self.assertEqual(validate_policy(self.policy), [])
        self.assertEqual(len(stage_ids(self.policy)), 6)

    def test_rejects_empty_official_path(self):
        bad = copy.deepcopy(self.policy)
        bad["official_path"] = []
        self.assertTrue(any("official_path" in e for e in validate_policy(bad)))

    def test_rejects_duplicate_stage_id(self):
        bad = copy.deepcopy(self.policy)
        bad["official_path"][1]["id"] = bad["official_path"][0]["id"]
        self.assertTrue(any("重复" in e for e in validate_policy(bad)))

    def test_rejects_unknown_detector(self):
        bad = copy.deepcopy(self.policy)
        bad["official_path"][0]["exit_criteria"]["detector"] = "magic"
        self.assertTrue(any("detector" in e for e in validate_policy(bad)))

    def test_rejects_empty_tokens(self):
        bad = copy.deepcopy(self.policy)
        bad["official_path"][0]["exit_criteria"]["tokens"] = []
        self.assertTrue(any("tokens" in e for e in validate_policy(bad)))

    def test_rejects_broken_regex(self):
        bad = copy.deepcopy(self.policy)
        bad["flag_regex"] = "flag{["
        self.assertTrue(any("flag_regex" in e for e in validate_policy(bad)))

    def test_rejects_scope_count_mismatch(self):
        bad = copy.deepcopy(self.policy)
        bad["scope_allowlist"] = ["only-one"]
        self.assertTrue(any("scope_allowlist" in e for e in validate_policy(bad)))

    def test_load_policy_reports_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{ not json", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_policy(path)

    def test_load_policy_reports_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                load_policy(Path(tmp) / "none.json")

    def test_load_policy_validates_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            broken = copy.deepcopy(self.policy)
            broken.pop("competition")
            path.write_text(json.dumps(broken, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_policy(path)


if __name__ == "__main__":
    unittest.main()
