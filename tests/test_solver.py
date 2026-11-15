import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, HTTPServer

from deepsick_attack.bench_client import Challenge, StartResult
from deepsick_attack.events import set_sink
from deepsick_attack.solver import (
    SolveContext,
    Toolkit,
    _extract_json_object,
    extract_flags,
    parse_targets,
    solve_challenge,
)

FLAG = "flag{st4ge_one_d3mo}"


class _Handler(BaseHTTPRequestHandler):
    """假靶标：/ 给首页，/secret 给 Flag，其余 404。"""

    def do_GET(self):
        if self.path == "/secret":
            body = "<html>ok " + FLAG + "</html>"
            self.send_response(200)
        elif self.path == "/":
            body = "<html><a href='/secret'>files</a></html>"
            self.send_response(200)
        else:
            body = "not found"
            self.send_response(404)
        payload = body.encode()
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _Server:
    def __enter__(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        return False


class FakeLLM:
    """按脚本逐轮返回动作，模拟模型行为。"""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def complete(self, system, messages=None, **kwargs):
        self.calls += 1
        if not self.replies:
            return {"text": json.dumps({"thought": "done", "flags": []})}
        return {"text": self.replies.pop(0)}


def make_challenge(**over):
    data = {
        "unique_code": "t-001",
        "description": "一个只读 Web 靶标，找出隐藏文件里的 flag。",
        "difficulty": "easy",
        "level": 1,
        "total_score": 100,
        "flag_count": 1,
        "correct_flag_count": 0,
        "is_completed": False,
        "container_status": "running",
    }
    data.update(over)
    return Challenge.from_dict(data)


class ParseTargetsTest(unittest.TestCase):
    def test_url_with_port(self):
        base, host, ports = parse_targets(["http://10.0.0.5:8080"])
        self.assertEqual(base, "http://10.0.0.5:8080")
        self.assertEqual(host, "10.0.0.5")
        self.assertEqual(ports, [8080])

    def test_bare_hostport(self):
        base, host, ports = parse_targets(["10.0.0.7:6379"])
        self.assertEqual(base, "http://10.0.0.7:6379")
        self.assertEqual(host, "10.0.0.7")
        self.assertIn(6379, ports)

    def test_multiple_addrs_keeps_first_http(self):
        base, host, ports = parse_targets(
            ["http://10.1.1.1:80", "http://10.1.1.1:9090", "garbage"])
        self.assertEqual(base, "http://10.1.1.1:80")
        self.assertEqual(host, "10.1.1.1")
        self.assertEqual(ports, [80, 9090])

    def test_empty(self):
        self.assertEqual(parse_targets([]), ("", "", []))


class ExtractFlagsTest(unittest.TestCase):
    def test_common_forms(self):
        text = "a flag{abc_123} b CTF{xx} c flag-deadbeef"
        found = extract_flags(text)
        self.assertIn("flag{abc_123}", found)
        self.assertIn("CTF{xx}", found)
        self.assertIn("flag-deadbeef", found)

    def test_dedup_case_insensitive(self):
        found = extract_flags("flag{a} FLAG{a}")
        self.assertEqual(len(found), 1)

    def test_ignore_short_noise(self):
        self.assertEqual(extract_flags("f{} {x}"), [])

    def test_empty(self):
        self.assertEqual(extract_flags(""), [])


class JsonParseTest(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(_extract_json_object('{"tool":"http_get"}'),
                         {"tool": "http_get"})

    def test_fenced(self):
        raw = '```json\n{"tool":"shell","args":{"command":"ls"}}\n```'
        self.assertEqual(_extract_json_object(raw)["tool"], "shell")

    def test_with_prose(self):
        raw = '我来看看。{"tool":"http_get","args":{"path":"/"}} 就这样。'
        self.assertEqual(_extract_json_object(raw)["args"], {"path": "/"})

    def test_invalid(self):
        self.assertIsNone(_extract_json_object("完全没有 JSON"))


class ToolkitTest(unittest.TestCase):
    def test_http_get_returns_body(self):
        with _Server() as srv:
            ctx = SolveContext(base_url=f"http://127.0.0.1:{srv.port}",
                               host="127.0.0.1", ports=[srv.port])
            out = Toolkit(ctx).run("http_get", {"path": "/secret"})
            self.assertIn(FLAG, out)
            self.assertIn("HTTP 200", out)

    def test_unknown_tool_is_reported(self):
        ctx = SolveContext(base_url="http://127.0.0.1:1", host="127.0.0.1")
        self.assertIn("未知工具", Toolkit(ctx).run("rm_rf", {}))

    def test_bad_args_do_not_raise(self):
        ctx = SolveContext(base_url="http://127.0.0.1:1", host="127.0.0.1")
        out = Toolkit(ctx).run("tcp_send", {"port": "not-a-number"})
        self.assertIn("port 必须是整数", out)

    def test_decode(self):
        ctx = SolveContext(base_url="http://x", host="x")
        self.assertIn("flag{a}", Toolkit(ctx).run(
            "decode", {"value": "ZmxhZ3thfQ==", "kind": "base64"}))

    def test_no_proxy_env_disables_fallback(self):
        """环境里没配代理时不应构造代理通道，避免每次失败都白重试一轮。"""
        ctx = SolveContext(base_url="http://127.0.0.1:1", host="127.0.0.1")
        toolkit = Toolkit(ctx)
        with patch("urllib.request.getproxies", return_value={}):
            self.assertIsNone(toolkit._env_proxy_opener())

    def test_direct_failure_reports_error_not_raise(self):
        ctx = SolveContext(base_url="http://127.0.0.1:1", host="127.0.0.1")
        toolkit = Toolkit(ctx, http_timeout=2)
        with patch("urllib.request.getproxies", return_value={}):
            out = toolkit.run("http_get", {"path": "/"})
        self.assertTrue("请求失败" in out or "HTTP" in out)


class SolveChallengeTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        set_sink(self.events.append)

    def tearDown(self):
        set_sink(None)

    def test_finds_flag_by_observation_regex(self):
        """模型没主动报 Flag，代码侧正则也要抓到。"""
        with _Server() as srv:
            llm = FakeLLM([json.dumps({"thought": "看首页", "tool": "http_get",
                                       "args": {"path": "/secret"}})])
            flags = solve_challenge(
                make_challenge(),
                StartResult("t-001", [f"http://127.0.0.1:{srv.port}"]),
                llm, deadline=__import__("time").time() + 30, max_steps=3)
        self.assertEqual(flags, [FLAG])
        self.assertTrue(any(e["event"] == "solve_flag_found" for e in self.events))

    def test_rejects_flag_without_evidence(self):
        """模型凭空报一个没出现过的 Flag，必须拒绝。"""
        with _Server() as srv:
            llm = FakeLLM([
                json.dumps({"thought": "编一个", "flags": ["flag{no_such_flag}"]}),
            ])
            flags = solve_challenge(
                make_challenge(),
                StartResult("t-001", [f"http://127.0.0.1:{srv.port}"]),
                llm, deadline=__import__("time").time() + 30, max_steps=2)
        self.assertEqual(flags, [])
        self.assertTrue(any(e["event"] == "solve_flag_rejected" for e in self.events))

    def test_accepts_claimed_flag_when_evidenced(self):
        with _Server() as srv:
            llm = FakeLLM([
                json.dumps({"thought": "看隐藏文件", "tool": "http_get",
                            "args": {"path": "/secret"}}),
                json.dumps({"thought": "拿到了", "flags": [FLAG]}),
            ])
            flags = solve_challenge(
                make_challenge(),
                StartResult("t-001", [f"http://127.0.0.1:{srv.port}"]),
                llm, deadline=__import__("time").time() + 30, max_steps=4)
        self.assertEqual(flags, [FLAG])

    def test_invalid_action_does_not_abort(self):
        with _Server() as srv:
            llm = FakeLLM([
                "我不太确定要做什么",
                json.dumps({"thought": "还是看首页", "tool": "http_get",
                            "args": {"path": "/secret"}}),
            ])
            flags = solve_challenge(
                make_challenge(),
                StartResult("t-001", [f"http://127.0.0.1:{srv.port}"]),
                llm, deadline=__import__("time").time() + 30, max_steps=4)
        self.assertEqual(flags, [FLAG])
        self.assertTrue(any(e["event"] == "solve_bad_action" for e in self.events))

    def test_no_target_returns_empty(self):
        flags = solve_challenge(make_challenge(), StartResult("t-001", []), FakeLLM([]))
        self.assertEqual(flags, [])
        self.assertTrue(any(e["event"] == "solve_no_target" for e in self.events))

    def test_deadline_stops_immediately(self):
        llm = FakeLLM([json.dumps({"tool": "http_get", "args": {}})])
        flags = solve_challenge(
            make_challenge(), StartResult("t-001", ["http://127.0.0.1:1"]),
            llm, deadline=__import__("time").time() - 1)
        self.assertEqual(flags, [])
        self.assertEqual(llm.calls, 0)


if __name__ == "__main__":
    unittest.main()
