import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import io
import json
import os
import unittest
import urllib.error
from unittest.mock import patch

from deepsick_attack.bench_client import (
    BenchConfigError,
    Challenge,
    ChallengesClient,
    CloseResult,
    DuplicateSubmit,
    StartResult,
    SubmitResult,
    ValidationError,
    run_benchmark,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def http_error(code, payload):
    body = json.dumps(payload).encode("utf-8")
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(body))


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.saved = {
            key: os.environ.pop(key, None)
            for key in ("BENCHMARK_TOKEN", "BENCHMARK_BASE_URL")
        }
        self.client = ChallengesClient(
            base_url="https://bench.example.com", token="token-123", timeout=5
        )

    def tearDown(self):
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def test_requires_platform_env(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(BenchConfigError):
                ChallengesClient()

    def test_list_challenges(self):
        payload = [{
            "unique_code": "web_sql_01", "description": "SQL injection",
            "difficulty": "easy", "level": 1, "total_score": 100,
            "flag_count": 2, "correct_flag_count": 1, "is_completed": False,
            "container_status": "available", "container_addr": ["10.0.1.5:8080"],
        }]
        with patch("urllib.request.urlopen", return_value=FakeResponse(payload)) as mocked:
            rows = self.client.list_challenges()
        request = mocked.call_args[0][0]
        self.assertEqual(request.full_url,
                         "https://bench.example.com/openapi/v1/challenges")
        self.assertEqual(request.get_header("Benchmark_token"), "token-123")
        self.assertEqual(rows[0].unique_code, "web_sql_01")
        self.assertEqual(rows[0].container_addr, ["10.0.1.5:8080"])

    def test_start_and_close_use_query_param(self):
        with patch("urllib.request.urlopen",
                   return_value=FakeResponse({"unique_code": "c1",
                                             "container_addr": ["10.0.0.1:80"]})):
            started = self.client.start_challenge("c1")
        self.assertIsInstance(started, StartResult)
        with patch("urllib.request.urlopen",
                   return_value=FakeResponse({"unique_code": "c1", "closed": True})) as mocked:
            closed = self.client.close_challenge("c1")
        self.assertIsInstance(closed, CloseResult)
        self.assertIn("unique_code=c1", mocked.call_args[0][0].full_url)

    def test_submit_flag_body(self):
        payload = {
            "correct": True, "awarded": 50, "cumulative_score": 80,
            "correct_flag_count": 2, "total_flag_count": 3,
            "matched_flag_index": 1,
        }
        with patch("urllib.request.urlopen", return_value=FakeResponse(payload)) as mocked:
            result = self.client.submit_flag("c1", "flag{ok}")
        request = mocked.call_args[0][0]
        self.assertEqual(request.full_url,
                         "https://bench.example.com/openapi/v1/challenges/submit")
        self.assertEqual(json.loads(request.data.decode("utf-8")),
                         {"unique_code": "c1", "flag": "flag{ok}"})
        self.assertIsInstance(result, SubmitResult)
        self.assertTrue(result.correct)

    def test_duplicate_maps_to_exception(self):
        error = http_error(409, {"code": "duplicate", "message": "dup", "detail": {}})
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(DuplicateSubmit):
                self.client.submit_flag("c1", "flag{ok}")

    def test_422_maps_to_validation_error(self):
        error = http_error(422, {"detail": [{"loc": ["body", "flag"]}]})
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(ValidationError):
                self.client.submit_flag("c1", "")


class FakeClient:
    def __init__(self):
        self.calls = []

    def list_challenges(self):
        self.calls.append("list")
        return [
            Challenge("done", "", "easy", 1, 100, 1, 1, True, "stopped", []),
            Challenge("todo", "", "easy", 1, 100, 1, 0, False, "stopped", []),
        ]

    def start_challenge(self, code):
        self.calls.append(("start", code))
        return StartResult(code, ["10.0.0.2:80"])

    def submit_flag(self, code, flag):
        self.calls.append(("submit", code, flag))
        return SubmitResult(True, 50, 50, 1, 1, 0)

    def close_challenge(self, code):
        self.calls.append(("close", code))
        return CloseResult(code, True)


class FlowTest(unittest.TestCase):
    def test_run_benchmark_order_and_finally_close(self):
        client = FakeClient()
        summary = run_benchmark(lambda ch, started: ["flag{ok}"], client=client)
        self.assertEqual(client.calls[0], "list")
        self.assertIn(("start", "todo"), client.calls)
        self.assertIn(("submit", "todo", "flag{ok}"), client.calls)
        self.assertEqual(client.calls[-1], ("close", "todo"))
        self.assertNotIn(("start", "done"), client.calls)
        self.assertEqual(summary["correct"], 1)
        self.assertEqual(summary["closed"], 1)

    def test_stub_solver_submits_nothing(self):
        client = FakeClient()
        summary = run_benchmark(client=client)
        self.assertEqual(summary["submitted"], 0)
        self.assertEqual(client.calls[-1], ("close", "todo"))


if __name__ == "__main__":
    unittest.main()
