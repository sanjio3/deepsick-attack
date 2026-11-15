import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import tempfile
import unittest

from deepsick_attack.bench_report import render, summarize


def write_log(rows):
    path = tempfile.mktemp(suffix=".jsonl")
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


class SummarizeTest(unittest.TestCase):
    """本地模式没有平台侧回放，这张聚合表就是唯一的诊断入口。"""

    def test_aggregates_steps_flags_and_stalls(self):
        path = write_log([
            {"event": "bench_started", "unique_code": "a-04", "pass_no": 1},
            {"event": "solve_step", "unique_code": "a-04", "step": 1,
             "tool": "shell", "thought": "先看首页", "output": "HTTP/1.1 200 OK"},
            {"event": "solve_repeat_blocked", "unique_code": "a-04", "step": 2},
            {"event": "solve_excluded", "unique_code": "a-04", "step": 3,
             "key": "上传绕过 @ /api/upload.php"},
            {"event": "solve_stuck_hint", "unique_code": "a-04", "step": 15},
            {"event": "solve_submit", "unique_code": "a-04", "step": 9,
             "correct": True},
            {"event": "solve_abandon", "unique_code": "a-04", "step": 40},
            {"event": "solve_step", "unique_code": "b-01", "step": 1,
             "tool": "shell", "output": "ok"},
        ])
        per = summarize(path)
        self.assertEqual(list(per), ["a-04", "b-01"])
        item = per["a-04"]
        self.assertEqual(item["steps"], 1)
        self.assertEqual(item["blocked"], 1)
        self.assertEqual(item["stuck"], 1)
        self.assertTrue(item["abandoned"])
        self.assertEqual(item["correct"], 1)
        self.assertEqual(item["excluded"], ["上传绕过 @ /api/upload.php"])

    def test_render_names_the_stall_reasons(self):
        path = write_log([
            {"event": "bench_started", "unique_code": "a-04", "pass_no": 2},
            {"event": "solve_repeat_blocked", "unique_code": "a-04"},
            {"event": "solve_abandon", "unique_code": "a-04"},
            {"event": "solve_excluded", "unique_code": "a-04",
             "key": "SQL 注入 @ /login"},
        ])
        text = render(path)
        self.assertIn("[a-04]", text)
        self.assertIn("轮次=[2]", text)
        self.assertIn("重复拦截", text)
        self.assertIn("提前收手", text)
        self.assertIn("SQL 注入 @ /login", text)

    def test_empty_log_is_explained_not_crashed(self):
        path = write_log([{"event": "bench_pass", "pass_no": 1}])
        self.assertIn("没有可聚合", render(path))

    def test_broken_lines_are_skipped(self):
        path = tempfile.mktemp(suffix=".jsonl")
        Path(path).write_text('{"event":"solve_step","unique_code":"x","step":1}\n'
                             "not json\n", encoding="utf-8")
        self.assertEqual(list(summarize(path)), ["x"])


if __name__ == "__main__":
    unittest.main()
