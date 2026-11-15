import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import tempfile
import unittest

from deepsick_attack.events import emit, get_log_file, set_log_file, set_sink


class LogFileTest(unittest.TestCase):
    """本地 Agent 模式没有平台侧会话记录，事件必须能自己落盘复盘。"""

    def setUp(self):
        self.path = tempfile.mktemp(suffix=".jsonl")
        set_sink(None)

    def tearDown(self):
        set_log_file(None)
        set_sink(None)
        Path(self.path).unlink(missing_ok=True)

    def _lines(self):
        return [json.loads(ln) for ln in
                Path(self.path).read_text(encoding="utf-8").splitlines() if ln.strip()]

    def test_every_event_lands_as_one_json_line(self):
        set_log_file(self.path)
        emit("solve_step", step=3, tool="shell", output="HTTP/1.1 200 OK")
        emit("solve_flag_found", step=4, flag="flag{x}")
        rows = self._lines()
        self.assertEqual([r["event"] for r in rows],
                         ["solve_step", "solve_flag_found"])
        self.assertEqual(rows[0]["step"], 3)
        self.assertEqual(get_log_file(), self.path)

    def test_sink_and_file_can_both_be_on(self):
        collected = []
        set_sink(collected.append)
        set_log_file(self.path)
        emit("bench_started", unique_code="a-04")
        self.assertEqual(len(collected), 1)
        self.assertEqual(self._lines()[0]["unique_code"], "a-04")

    def test_appends_instead_of_truncating(self):
        set_log_file(self.path)
        emit("first")
        set_log_file(None)
        set_log_file(self.path)
        emit("second")
        self.assertEqual([r["event"] for r in self._lines()], ["first", "second"])

    def test_none_closes(self):
        set_log_file(self.path)
        emit("only")
        set_log_file(None)
        self.assertIsNone(get_log_file())


if __name__ == "__main__":
    unittest.main()
