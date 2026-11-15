import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import tempfile
import unittest
from pathlib import Path

from deepsick_attack.blackboard import Blackboard
from deepsick_attack.models import Fact, Hint, Intent, TraceStep


class BlackboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bb = Blackboard(self.tmp.name, 7)

    def test_creates_state_files(self):
        root = Path(self.tmp.name) / "target_7"
        for name in ("intents.jsonl", "facts.jsonl", "hints.jsonl",
                     "trace.jsonl", "LIVE_CRED.txt"):
            self.assertTrue((root / name).exists())
        self.assertTrue((root / "evidence").is_dir())

    def test_intent_event_sourcing_keeps_latest_state(self):
        self.bb.add_intent(Intent(id="i1", stage="recon", action="a", status="running"))
        self.bb.add_intent(Intent(id="i1", stage="recon", action="a", status="done"))
        state = self.bb.load_state()
        self.assertEqual(len(state["intents"]), 1)
        self.assertEqual(state["intents"][0]["status"], "done")

    def test_evidence_is_written_verbatim(self):
        path = self.bb.write_evidence("i1-recon", "curl -v target", "HTTP/1.1 200 OK")
        content = Path(path).read_text(encoding="utf-8")
        self.assertIn("COMMAND:", content)
        self.assertIn("curl -v target", content)
        self.assertIn("HTTP/1.1 200 OK", content)

    def test_state_roundtrip_and_snapshot(self):
        self.bb.add_intent(Intent(id="i1", stage="recon", action="probe"))
        self.bb.add_fact(Fact(
            id="f1", intent_id="i1", summary="端口开放", detail="80",
            confidence="observed", stage="recon", technique="T1595",
            evidence_paths=["e1"],
        ))
        self.bb.add_hint(Hint(id="h1", stage="recon", text="换端口探测",
                              source="playbook"))
        self.bb.append_trace(TraceStep(
            seq=1, intent_id="i1", stage="recon", technique="T1595",
            action="probe", tool="offline", observation_ref="e1",
            evidence_paths=["e1"], verdicts=[], fact_id="f1", path_points=0.0,
        ))
        state = self.bb.load_state()
        self.assertEqual(len(state["facts"]), 1)
        self.assertEqual(len(state["hints"]), 1)
        self.assertEqual(len(state["trace"]), 1)
        snapshot = self.bb.snapshot_text()
        self.assertIn("FACT f1", snapshot)
        self.assertIn("STEP 1", snapshot)
        self.assertIn("HINT", snapshot)


if __name__ == "__main__":
    unittest.main()
