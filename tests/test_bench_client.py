import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import io
import json
import os
import unittest
import urllib.error
from unittest.mock import patch

from deepsick_attack.bench_client import (  # noqa: E402
    MAX_WORKERS,
    _workers,
    BenchConfigError,
    Challenge,
    ChallengesClient,
    ResourceUnavailable,
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
    def setUp(self):
        # 列表空轮询不再等 15 秒
        os.environ["BENCH_IDLE_SECONDS"] = "0"

    def tearDown(self):
        os.environ.pop("BENCH_IDLE_SECONDS", None)

    def test_run_benchmark_order_and_finally_close(self):
        client = FakeClient()
        summary = run_benchmark(lambda ch, started: ["flag{ok}"], client=client)
        self.assertEqual(client.calls[0], "list")
        self.assertIn(("start", "todo"), client.calls)
        self.assertIn(("submit", "todo", "flag{ok}"), client.calls)
        # 关闭必须在提交之后；列表会再轮询一次，所以不能断言 close 是最后一个动作
        self.assertGreater(client.calls.index(("close", "todo")),
                           client.calls.index(("submit", "todo", "flag{ok}")))
        self.assertNotIn(("start", "done"), client.calls)
        self.assertEqual(summary["correct"], 1)
        self.assertEqual(summary["closed"], 1)

    def test_stub_solver_submits_nothing(self):
        client = FakeClient()
        summary = run_benchmark(client=client)
        self.assertEqual(summary["submitted"], 0)
        self.assertIn(("close", "todo"), client.calls)

    def test_solver_exception_does_not_kill_the_run(self):
        """单题抛异常必须只丢这一题，整轮继续（实跑里就是这里把整轮带走了）。"""
        client = FakeClient()

        def boom(ch, started):
            raise RuntimeError("模拟解题器崩溃")

        summary = run_benchmark(boom, client=client, passes=1)
        self.assertIn(("close", "todo"), client.calls)
        self.assertEqual(summary["errors"], 1)
        self.assertEqual(summary["closed"], 1)

    def test_start_error_skips_challenge_and_continues(self):
        class FlakyClient(FakeClient):
            def start_challenge(self, code):
                self.calls.append(("start", code))
                raise ResourceUnavailable("resource_unavailable", "no slot", {}, 409)

        client = FlakyClient()
        summary = run_benchmark(lambda ch, started: [], client=client)
        self.assertEqual(summary["started"], 0)
        self.assertEqual(summary["errors"], 3)  # 三次尝试后放弃该题
        self.assertEqual(summary["closed"], 0)

    def test_list_is_repolled_for_late_challenges(self):
        """平台下发的列表可能只是当下可启动的子集，处理完要再取一次。"""
        class LateClient(FakeClient):
            def __init__(self):
                super().__init__()
                self.rounds = 0

            def list_challenges(self):
                self.calls.append("list")
                self.rounds += 1
                if self.rounds == 1:
                    return [Challenge("a", "", "easy", 1, 100, 1, 0, False, "running", [])]
                if self.rounds == 2:
                    return [Challenge("a", "", "easy", 1, 100, 1, 0, False, "running", []),
                            Challenge("b", "", "easy", 1, 100, 1, 0, False, "running", [])]
                return []

        client = LateClient()
        summary = run_benchmark(lambda ch, started: [], client=client)
        starts = [c for c in client.calls if isinstance(c, tuple) and c[0] == "start"]
        self.assertEqual([s[1] for s in starts], ["a", "b"])
        self.assertEqual(summary["started"], 2)


class ConcurrencyTest(unittest.TestCase):
    """平台允许同时 3 个实例，串行跑根本吃不满窗口。"""

    def setUp(self):
        os.environ["BENCH_IDLE_SECONDS"] = "0"
        os.environ["BENCH_RETRY_DELAY"] = "0"

    def tearDown(self):
        os.environ.pop("BENCH_IDLE_SECONDS", None)
        os.environ.pop("BENCH_RETRY_DELAY", None)

    def test_concurrency_capped_at_three(self):
        import threading as th

        class Gauge:
            def __init__(self):
                self.lock = th.Lock()
                self.active = 0
                self.peak = 0

            def enter(self):
                with self.lock:
                    self.active += 1
                    self.peak = max(self.peak, self.active)

            def leave(self):
                with self.lock:
                    self.active -= 1

        gauge = Gauge()

        class SlowClient(FakeClient):
            def list_challenges(self):
                self.calls.append("list")
                return [Challenge(f"c{i}", "", "easy", 1, 100, 1, 0, False,
                                  "running", []) for i in range(6)]

            def start_challenge(self, code):
                gauge.enter()
                self.calls.append(("start", code))
                return StartResult(code, ["10.0.0.2:80"])

            def close_challenge(self, code):
                gauge.leave()
                self.calls.append(("close", code))
                return CloseResult(code, True)

        def slow_solver(ch, started):
            time.sleep(0.12)
            return []

        summary = run_benchmark(slow_solver, client=SlowClient(), workers=3,
                                passes=1)
        self.assertEqual(summary["started"], 6)
        self.assertEqual(summary["closed"], 6)
        self.assertLessEqual(gauge.peak, 3, f"并发超过 3：{gauge.peak}")

    def test_workers_env_is_clamped(self):
        os.environ["BENCH_WORKERS"] = "99"
        try:
            self.assertEqual(_workers(), MAX_WORKERS)
        finally:
            os.environ.pop("BENCH_WORKERS", None)


class SecondPassTest(unittest.TestCase):
    """第一轮求速度、第二轮求深度：只有没解出来的题才翻打，且换一套攻击面提示。"""

    def setUp(self):
        os.environ["BENCH_IDLE_SECONDS"] = "0"
        os.environ["BENCH_RETRY_DELAY"] = "0"

    def tearDown(self):
        os.environ.pop("BENCH_IDLE_SECONDS", None)
        os.environ.pop("BENCH_RETRY_DELAY", None)

    def _client(self, codes):
        class Client(FakeClient):
            def list_challenges(self):
                self.calls.append("list")
                return [Challenge(c, "", "easy", 1, 100, 1, 0, False, "running", [])
                        for c in codes]

        return Client()

    def test_second_pass_only_retries_unsolved_with_hint(self):
        client = self._client(["win", "lose"])
        seen = []

        def solver(ch, started):
            seen.append((ch.unique_code, "第二轮" in (ch.description or "")))
            return ["flag{x}"] if ch.unique_code == "win" else []

        summary = run_benchmark(solver, client=client, passes=2)
        # win 第一轮就解出来了，第二轮不该再启动它；lose 要带着提示重打一次
        self.assertCountEqual(seen, [("win", False), ("lose", False), ("lose", True)])
        self.assertEqual(summary["passes"], 2)
        self.assertEqual(summary["started"], 3)
        self.assertEqual(summary["closed"], 3)

    def test_passes_env_controls_rounds(self):
        os.environ["BENCH_RETRY_PASSES"] = "1"
        try:
            seen = []
            client = self._client(["x"])

            def solver(ch, started):
                seen.append(ch.unique_code)
                return []

            summary = run_benchmark(solver, client=client)
            self.assertEqual(seen, ["x"])
            self.assertEqual(summary["passes"], 1)
        finally:
            os.environ.pop("BENCH_RETRY_PASSES", None)

    def test_only_filters_to_one_challenge(self):
        seen = []

        def solver(ch, started):
            seen.append(ch.unique_code)
            return []

        client = self._client(["a-01", "a-04", "a-11"])
        summary = run_benchmark(solver, client=client, passes=1, only="a-04")
        self.assertEqual(seen, ["a-04"])
        self.assertEqual(summary["started"], 1)


if __name__ == "__main__":
    unittest.main()
