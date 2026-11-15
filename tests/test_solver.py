"""solver / agent_loop 回归测试。

新架构下 solve_challenge = 代码侦察打底 + AgentRunner（原生 tool_use 循环）。
所以循环行为测试全部改成脚本化假 client（FakeClient 直接返回 tool_use 块），
不再喂 JSON 文本。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import re
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from deepsick_attack import sense
from deepsick_attack.bench_client import Challenge, StartResult, _accepts_submit
from deepsick_attack.events import set_sink
from deepsick_attack.facts import Fact, FactBoard
from deepsick_attack.flags import extract_flags
from deepsick_attack.playbook import Candidate, detect, propose
from deepsick_attack.solver import (
    SolveContext,
    Toolkit,
    _extract_json_object,
    _attack_family,
    _choose_base_url,
    parse_targets,
    recon_scan,
    solve_challenge,
)

FLAG = "flag{st4ge_one_d3mo}"


class _Handler(BaseHTTPRequestHandler):
    """假靶标：/ 给首页，/secret 给 Flag，/trap 模拟主动防御，其余 404。"""

    def do_GET(self):
        if self.path == "/secret":
            body, code = "<html>ok " + FLAG + "</html>", 200
        elif self.path == "/trap":
            body, code = "<html>intrusion detected, you have been logged</html>", 403
        elif self.path == "/many":
            body = " ".join(f"flag{{bulk_{i:02d}_value}}" for i in range(20))
            code = 200
        elif self.path == "/":
            body, code = "<html><a href='/secret'>files</a></html>", 200
        else:
            body, code = "not found", 404
        payload = body.encode()
        self.send_response(code)
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


class _BannerServer:
    """只吐一段 banner 的裸 TCP 服务，用于验证协议判定。"""

    def __init__(self, banner: bytes):
        self.banner = banner
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.sendall(self.banner)
                conn.settimeout(0.3)
                try:
                    conn.recv(1024)
                except OSError:
                    pass
            finally:
                conn.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        return False


class FakeClient:
    """新协议的假 client：脚本化返回 tool_use 块。

    script 的每个元素是一轮里的若干 (tool_name, input) 调用，按顺序消费；
    脚本耗尽后返回纯文本（触发 idle 提醒）。
    """

    def __init__(self, script):
        self.script = [list(turn) for turn in script]
        self.calls = 0
        self.system_prompts = []
        self.hist = []

    def chat(self, system, messages, tools=None, **kwargs):
        self.calls += 1
        self.system_prompts.append(system)
        self.hist.append(json.loads(json.dumps(messages)))
        if not self.script:
            return {"content": [{"type": "text", "text": "脚本已耗尽"}],
                    "stop_reason": "end_turn"}
        batch = self.script.pop(0)
        blocks = []
        for i, (name, inp) in enumerate(batch):
            blocks.append({"type": "text", "text": f"调用 {name} #{i}"})
            blocks.append({"type": "tool_use", "id": f"c{self.calls}-{i}",
                           "name": name, "input": inp})
        return {"content": blocks, "stop_reason": "tool_use"}


def make_challenge(**over):
    data = {
        "unique_code": "t-001",
        "description": "一个只读 Web 靶标，找出隐藏文件里的 flag。",
        "difficulty": "easy", "level": 1, "total_score": 100, "flag_count": 1,
        "correct_flag_count": 0, "is_completed": False,
        "container_status": "running",
    }
    data.update(over)
    return Challenge.from_dict(data)


def _ctx(port, base_url=""):
    return SolveContext(host="127.0.0.1", hint_ports=[port],
                        base_url=base_url or f"http://127.0.0.1:{port}")


def _board(host="h"):
    """每个用例独立的事实板目录，避免上一轮残留影响判定。"""
    return FactBoard(host=host, path=tempfile.mktemp(suffix=".jsonl"))


class ParseTargetsTest(unittest.TestCase):
    def test_http_addr(self):
        self.assertEqual(parse_targets(["http://10.0.0.5:8080"]),
                         ("10.0.0.5", [8080]))

    def test_bare_hostport_is_not_turned_into_http_url(self):
        """关键回归：只给 :22 时不能再臆造 http://host:22 当入口。"""
        host, ports = parse_targets(["10.0.0.7:22"])
        self.assertEqual(host, "10.0.0.7")
        self.assertEqual(ports, [22])

    def test_multiple_addrs(self):
        self.assertEqual(parse_targets(["http://10.1.1.1:80", "http://10.1.1.1:9090"]),
                         ("10.1.1.1", [80, 9090]))

    def test_empty(self):
        self.assertEqual(parse_targets([]), ("", []))


class SenseTest(unittest.TestCase):
    def test_scan_finds_open_port(self):
        with _Server() as srv:
            self.assertIn(srv.port, sense.scan("127.0.0.1", [srv.port, srv.port + 1]))

    def test_fingerprint_http(self):
        with _Server() as srv:
            info = sense.fingerprint("127.0.0.1", srv.port)
            self.assertEqual(info["proto"], "http")
            self.assertEqual(info["http_status"], 200)

    def test_fingerprint_ssh_banner(self):
        with _BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n") as srv:
            info = sense.fingerprint("127.0.0.1", srv.port)
            self.assertEqual(info["proto"], "ssh")
            self.assertIn("OpenSSH", info["banner"])

    def test_expand_ports_focused_on_hints(self):
        """默认只扫提示端口邻域——共享宿主机上扫全端口会打到别的题。"""
        ports = sense.expand_ports([30001])
        self.assertIn(30001, ports)
        self.assertIn(30002, ports)
        self.assertLess(len(ports), 40)

    def test_expand_ports_deep_falls_back_to_top(self):
        ports = sense.expand_ports([30001], deep=True)
        self.assertIn(30001, ports)
        self.assertIn(80, ports)

    def test_expand_ports_without_hints_scans_top(self):
        self.assertIn(22, sense.expand_ports([]))


class FactBoardTest(unittest.TestCase):
    def test_dedupe_and_snapshot(self):
        board = _board("10.0.0.1")
        fact = Fact("service", "10.0.0.1:80", "10.0.0.1:80 http")
        self.assertTrue(board.add(fact))
        self.assertFalse(board.add(fact))
        self.assertIn("10.0.0.1:80", board.snapshot())

    def test_honeypot_flag_sorts_to_top(self):
        board = _board()
        board.add(Fact("service", "h:80", "h:80 http"))
        board.add(Fact("service", "h:8080", "h:8080 http", "honeypot"))
        self.assertEqual(board.services()[1].risk, "honeypot")
        self.assertIn("h:8080", board.risky())

    def test_tried_persisted(self):
        path = tempfile.mktemp(suffix=".jsonl")
        board = FactBoard(host="h", path=path)
        board.mark_tried("http:80:home")
        again = FactBoard(host="h", path=path)
        self.assertIn("http:80:home", again.tried)

    def test_truncated_state_does_not_crash(self):
        path = tempfile.mktemp(suffix=".jsonl")
        Path(path).write_text('{"broken json\n', encoding="utf-8")
        FactBoard(host="h", path=path)  # 不应抛异常


class PlaybookTest(unittest.TestCase):
    def test_propose_http_candidates(self):
        board = _board("10.0.0.9")
        board.add(Fact("service", "10.0.0.9:80", "10.0.0.9:80 http"))
        items = propose(board)
        ids = [c.id for c in items]
        self.assertIn("http:80:home", ids)
        self.assertIn("http:80:missing", ids)

    def test_no_services_prompts_scan(self):
        board = _board("10.0.0.9")
        self.assertEqual(propose(board)[0].id, "meta:scan")

    def test_tried_candidates_are_dropped(self):
        board = _board()
        board.add(Fact("service", "h:80", "h:80 http"))
        board.mark_tried("http:80:home")
        self.assertNotIn("http:80:home", [c.id for c in propose(board, 20)])

    def test_risky_service_candidates_sorted_last(self):
        board = _board()
        board.add(Fact("service", "h:80", "h:80 http"))
        board.add(Fact("service", "h:8080", "h:8080 http", "honeypot"))
        items = propose(board, 20)
        risks = [c.risk for c in items]
        self.assertEqual(risks, sorted(risks, key=lambda r: r == "high"))

    def test_detect_flag_and_tripwire(self):
        probe = detect("HTTP 200\n\nhere " + FLAG + " intrusion detected")
        self.assertIn(FLAG, probe.flags)
        self.assertIsNotNone(probe.tripwire)
        self.assertEqual(probe.status, 200)

    def test_detect_too_easy(self):
        self.assertIsNotNone(detect("root:x:0:0:root:/root:/bin/bash").too_easy)


class ExtractFlagsTest(unittest.TestCase):
    def test_common_forms(self):
        found = extract_flags("a flag{abc_123} b CTF{xx} c flag-deadbeef")
        self.assertIn("flag{abc_123}", found)
        self.assertIn("CTF{xx}", found)
        self.assertIn("flag-deadbeef", found)

    def test_dedup_case_insensitive(self):
        self.assertEqual(len(extract_flags("flag{a} FLAG{a}")), 1)

    def test_ignore_short_noise(self):
        self.assertEqual(extract_flags("f{} {x}"), [])

    def test_empty(self):
        self.assertEqual(extract_flags(""), [])

    def test_strict_mode_only_strong(self):
        text = "flag{abc_123} 恭喜，答案是 secret_ab{real_one}"
        self.assertEqual(extract_flags(text, strict=True), ["flag{abc_123}"])


class CodeFragmentGateTest(unittest.TestCase):
    """可疑即提交，但代码片段必须挡住——上一轮把 .cls{a:b} 交了 5 次。"""

    def test_css_fragment_rejected(self):
        self.assertEqual(extract_flags("<style>.cls{a:b}</style>"), [])

    def test_js_object_rejected(self):
        self.assertEqual(extract_flags("var x = {a:1}; foo{bar:2}"), [])

    def test_json_blob_rejected(self):
        self.assertEqual(extract_flags('{"user":"admin","ok":true}'), [])

    def test_long_weak_candidate_accepted(self):
        """够长的弱特征直接放行——宁可交给平台判，也不要 0 次提交。"""
        self.assertIn("xq7{alpha_beta_9}", extract_flags("xq7{alpha_beta_9}"))

    def test_short_weak_without_context_rejected(self):
        self.assertEqual(extract_flags("zzz{abc}"), [])

    def test_short_weak_with_context_accepted(self):
        self.assertEqual(extract_flags("答案是 zzz{abc}"), ["zzz{abc}"])


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
            out = Toolkit(_ctx(srv.port)).run("http_get", {"path": "/secret"})
            self.assertIn(FLAG, out)
            self.assertIn("HTTP 200", out)

    def test_unknown_tool_is_reported(self):
        self.assertIn("未知工具", Toolkit(_ctx(1)).run("rm_rf", {}))

    def test_bad_args_do_not_raise(self):
        out = Toolkit(_ctx(1)).run("tcp_send", {"port": "not-a-number"})
        self.assertIn("port 必须是整数", out)

    def test_decode(self):
        self.assertIn("flag{a}", Toolkit(_ctx(1)).run(
            "decode", {"value": "ZmxhZ3thfQ==", "kind": "base64"}))

    def test_no_proxy_env_disables_fallback(self):
        toolkit = Toolkit(_ctx(1))
        with patch("urllib.request.getproxies", return_value={}):
            self.assertIsNone(toolkit._env_proxy_opener())

    def test_direct_failure_reports_error_not_raise(self):
        toolkit = Toolkit(_ctx(1), http_timeout=2)
        with patch("urllib.request.getproxies", return_value={}):
            out = toolkit.run("http_get", {"path": "/"})
        self.assertTrue("请求失败" in out or "HTTP" in out)

    def test_ssh_tools_degrade_without_paramiko(self):
        """镜像没带 vendor 依赖时给说明，不能抛异常打断主流程。"""
        ctx = _ctx(22)
        with patch.dict(sys.modules, {"paramiko": None}):
            out = Toolkit(ctx).run("ssh_audit", {"port": 22})
        self.assertIn("paramiko", out)


class ReconTest(unittest.TestCase):
    def test_recon_records_service_and_base_url(self):
        with _Server() as srv:
            board = _board("127.0.0.1")
            ctx = SolveContext(host="127.0.0.1", hint_ports=[srv.port],
                               board=board)
            text = recon_scan(ctx, board)
            self.assertTrue(any(":80" in f.detail or str(srv.port) in f.detail
                                for f in board.services()))
            self.assertIn("http", text)
            self.assertTrue(ctx.base_url.startswith("http://127.0.0.1"))


class BaseUrlChoiceTest(unittest.TestCase):
    """入口选择是上一轮 0 分的直接原因之一，单独钉住。"""

    def test_prefers_hint_port(self):
        protos = {8080: "http", 30001: "http"}
        self.assertEqual(_choose_base_url("h", protos, [30001]),
                         "http://h:30001")

    def test_falls_back_to_scanned_http_when_hint_is_not_web(self):
        self.assertEqual(_choose_base_url("h", {22: "ssh", 8080: "http"}, [22]),
                         "http://h:8080")

    def test_no_http_service_means_no_guessed_url(self):
        """只给 :22 时不能臆造 http://host:22 —— 那会往 SSH 端口发 40 步 HTTP。"""
        self.assertEqual(_choose_base_url("h", {22: "ssh"}, [22]), "")


class SshOnlyChallengeTest(unittest.TestCase):
    def test_ssh_only_target_gets_ssh_candidates(self):
        with _BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n") as srv:
            board = _board("127.0.0.1")
            ctx = SolveContext(host="127.0.0.1", hint_ports=[srv.port],
                               board=board)
            recon_scan(ctx, board)
            self.assertEqual(ctx.base_url, "")
            ids = [c.id for c in propose(board)]
        self.assertTrue(any(i.startswith("ssh:") for i in ids))
        self.assertFalse(any(i.startswith("http:") for i in ids))


class SessionTest(unittest.TestCase):
    """会话是这一版的核心能力：没有它做不了反弹 shell / 交互式 ssh / nc。"""

    def test_start_send_read_roundtrip(self):
        toolkit = Toolkit(_ctx(1))
        try:
            out = toolkit.run("session_start", {"command": "cat", "use_pty": False})
            self.assertIn("已创建会话", out)
            sid = int(re.search(r"id=(\d+)", out).group(1))
            # send 自带一次读取，方便小模型少走一步
            got = toolkit.run("session_send", {"id": sid, "text": "hello-session"})
            self.assertIn("hello-session", got)
            self.assertIn("id=", toolkit.session_list())
            self.assertIn("已关闭", toolkit.run("session_kill", {"id": sid}))
            self.assertNotIn("id=", toolkit.session_list())
        finally:
            toolkit.sessions.close_all()

    def test_read_captures_late_output(self):
        """session_read 要能单独拿到「后来才产生」的输出（不靠 send 捎带）。"""
        toolkit = Toolkit(_ctx(1))
        try:
            # 3 秒后才出输出：要晚于 session_start 自带的初始读取窗口（约 1.8s），
            # 否则会被初始读取吃掉，测不到「后来才产生」这条路径。
            toolkit.run("session_start",
                        {"command": "sleep 3; echo delayed-marker", "use_pty": False})
            got = toolkit.run("session_read", {"id": 1, "wait": 6})
            self.assertIn("delayed-marker", got)
        finally:
            toolkit.sessions.close_all()

    def test_missing_session_is_reported(self):
        toolkit = Toolkit(_ctx(1))
        self.assertIn("没有 id=99", toolkit.run("session_read", {"id": 99}))


class ShellTimeoutTest(unittest.TestCase):
    """超时必须真的把命令杀掉，不能只杀直接子进程。"""

    def test_timeout_returns_quickly_and_reports(self):
        ctx = SolveContext(host="127.0.0.1", hint_ports=[])
        tk = Toolkit(ctx, shell_timeout=1)
        started = time.time()
        out = tk.shell("sleep 30")
        elapsed = time.time() - started
        self.assertLess(elapsed, 12, f"超时没生效，实际 {elapsed:.1f}s")
        self.assertIn("超时", out)
        self.assertIn("sleep 30", out)

    def test_timeout_kills_grandchild(self):
        ctx = SolveContext(host="127.0.0.1", hint_ports=[])
        tk = Toolkit(ctx, shell_timeout=1)
        started = time.time()
        tk.shell("bash -c 'sleep 30' ; true")
        self.assertLess(time.time() - started, 12)


class TripwirePrecisionTest(unittest.TestCase):
    """蜜罐判据只认成句话术。单个词会把 nmap/curl 的正常输出当告警。"""

    def test_nmap_status_line_is_not_tripwire(self):
        probe = detect("Some closed ports may be reported as filtered due to "
                       "--defeat-rst-ratelimit")
        self.assertFalse(probe.tripwire)

    def test_curl_error_is_not_tripwire(self):
        self.assertFalse(detect("curl: (7) Failed to connect: connection refused").tripwire)
        self.assertFalse(detect("access blocked by network policy").tripwire)

    def test_real_banner_is_tripwire(self):
        self.assertTrue(detect("检测到攻击，已记录你的 IP").tripwire)
        self.assertTrue(detect("Intrusion Detected: your ip has been blocked").tripwire)


class ReconHintClosedTest(unittest.TestCase):
    """提示端口全关闭时，观测里必须明说，避免模型反复 nmap -p- 烧预算。"""

    def test_closed_hint_port_adds_note(self):
        from unittest import mock
        ctx = SolveContext(host="10.0.0.9", hint_ports=[5000])
        board = FactBoard(path=tempfile.mktemp(suffix=".jsonl"), host=ctx.host)
        with mock.patch.object(sense, "scan", return_value=[]), \
             mock.patch.object(sense, "mdns_services", return_value=[]):
            text = recon_scan(ctx, board, emit_events=False)
        self.assertIn("5000", text)
        self.assertIn("不要用 nmap -p-", text)


class AcceptsSubmitTest(unittest.TestCase):
    def test_detects_kwarg(self):
        self.assertTrue(_accepts_submit(lambda a, b, submit=None: None))
        self.assertFalse(_accepts_submit(lambda a, b: None))

    def test_detects_kwargs(self):
        self.assertTrue(_accepts_submit(lambda a, b, **kw: None))


class BulkProbeTest(unittest.TestCase):
    """敏感路径探测从「模型一步步试」改成「代码一次打完」。"""

    def test_reports_only_paths_that_exist(self):
        with _Server() as srv:
            hits = sense.bulk_probe(f"http://127.0.0.1:{srv.port}",
                                    ["/secret", "/definitely-not-here"])
        self.assertEqual([h["path"] for h in hits], ["/secret"])
        self.assertEqual(hits[0]["status"], 200)

    def test_forbidden_counts_as_alive(self):
        """403 说明路径存在，只是要绕过——不能当没命中丢掉。"""
        with _Server() as srv:
            hits = sense.bulk_probe(f"http://127.0.0.1:{srv.port}", ["/trap"])
        self.assertEqual([(h["path"], h["status"]) for h in hits], [("/trap", 403)])

    def test_bad_base_url_is_a_noop(self):
        self.assertEqual(sense.bulk_probe(""), [])

    def test_recon_folds_probe_hits_into_facts_and_text(self):
        from unittest import mock
        with _Server() as srv:
            board = _board("127.0.0.1")
            ctx = SolveContext(host="127.0.0.1", hint_ports=[srv.port],
                               board=board)
            with mock.patch.object(sense, "PROBE_PATHS",
                                   ("/secret", "/definitely-not-here")):
                text = recon_scan(ctx, board, emit_events=False)
            keys = [f.key for f in board.of("route")]
        self.assertIn("敏感路径命中", text)
        self.assertIn("probe:/secret", keys)
        self.assertNotIn("probe:/definitely-not-here", keys)


class AttackFamilyTest(unittest.TestCase):
    def test_upload_family_and_path(self):
        self.assertEqual(
            _attack_family("curl -F 'f=@a.png;filename=a.php' http://h:80/upload.php"),
            ("上传绕过", "/upload.php"))

    def test_idor_family(self):
        self.assertEqual(_attack_family("curl -s 'http://h/order?id=2'"), ("越权 id", "/order"))

    def test_plain_recon_has_no_family(self):
        self.assertEqual(_attack_family("curl -sS http://h:80/"), ("", ""))

    def test_reading_an_upload_endpoint_is_not_an_upload_attempt(self):
        """a-04 的坑：读一次 /api/upload.php 被记成「上传绕过已排除」。"""
        self.assertEqual(_attack_family("curl -sS http://h/api/upload.php"), ("", ""))

    def test_multipart_really_is_an_upload_attempt(self):
        self.assertEqual(
            _attack_family("curl -F 'f=@a.png' -H 'X-API-Key: k' "
                           "http://h/api/upload.php")[0], "上传绕过")

    def test_shell_variable_path_is_not_recorded(self):
        family, path = _attack_family("for p in a; do curl -F x http://h/$p; done")
        self.assertEqual(family, "上传绕过")
        self.assertEqual(path, "", "变量路径不能当真实路径记账")


class SolveChallengeTest(unittest.TestCase):
    """新协议端到端：FakeClient 直接发 tool_use，走完整循环。"""

    def setUp(self):
        self.events = []
        set_sink(self.events.append)

    def tearDown(self):
        set_sink(None)

    def _events(self, name):
        return [e for e in self.events if e["event"] == name]

    def test_no_target_returns_empty(self):
        flags = solve_challenge(make_challenge(), StartResult("t-001", []),
                                FakeClient([]))
        self.assertEqual(flags, [])
        self.assertTrue(self._events("solve_no_target"))

    def test_deadline_stops_immediately(self):
        client = FakeClient([])
        flags = solve_challenge(make_challenge(), StartResult("t-001", ["127.0.0.1:1"]),
                                client, deadline=time.time() - 1)
        self.assertEqual(flags, [])
        self.assertEqual(client.calls, 0)

    def test_shell_output_flag_auto_submitted(self):
        """shell 工具的输出里有 flag 就自动交——确定性副驾驶不占模型回合。"""
        with _Server() as srv:
            client = FakeClient([
                [("shell", {"command": f"curl -s -m 6 http://127.0.0.1:{srv.port}/secret"})],
                [("finish", {"summary": "flag 已交"})],
            ])
            flags = solve_challenge(
                make_challenge(), StartResult("t-001", [f"127.0.0.1:{srv.port}"]),
                client, deadline=time.time() + 60, max_steps=6)
        self.assertEqual(flags, [FLAG])
        self.assertTrue(self._events("recon_scan"))
        # flag 数够了走 agent_all_flags 提前收尾，否则等 finish 工具
        self.assertTrue(self._events("agent_finish") or self._events("agent_all_flags"))

    def test_submit_tool_gets_platform_feedback(self):
        with _Server() as srv:
            calls = []

            class Result:
                correct = True
                correct_flag_count = 1
                total_flag_count = 1

            client = FakeClient([
                [("submit_flag", {"flags": [FLAG]})],
                [("finish", {"summary": "done"})],
            ])
            flags = solve_challenge(
                make_challenge(), StartResult("t-001", [f"127.0.0.1:{srv.port}"]),
                client, deadline=time.time() + 60, max_steps=4,
                submit=lambda f: (calls.append(f), Result())[1])
        self.assertEqual(calls, [FLAG])
        self.assertEqual(flags, [FLAG])
        self.assertTrue(self._events("solve_submit"))

    def test_claimed_flag_without_evidence_still_submitted(self):
        """模型编的 flag 也交给平台判——0 次提交拿不到任何反馈。"""
        client = FakeClient([
            [("submit_flag", {"flags": ["flag{no_such_flag}"]})],
            [("finish", {"summary": "试过了"})],
        ])
        flags = solve_challenge(make_challenge(), StartResult("t-001", ["127.0.0.1:1"]),
                                client, deadline=time.time() + 30, max_steps=3)
        self.assertIn("flag{no_such_flag}", flags)

    def test_finish_ends_loop(self):
        client = FakeClient([[("finish", {"summary": "没找到"})]])
        solve_challenge(make_challenge(), StartResult("t-001", ["127.0.0.1:1"]),
                        client, deadline=time.time() + 30, max_steps=5)
        self.assertEqual(client.calls, 1)
        self.assertTrue(self._events("agent_finish"))


class LoopMechanicsTest(unittest.TestCase):
    """agent 循环的机制测试：角色切换、工具容错、上下文 GC。"""

    def setUp(self):
        self.events = []
        set_sink(self.events.append)

    def tearDown(self):
        set_sink(None)

    def test_planner_nudge_after_close_intent(self):
        """intent 收口后下一轮必须注入 planner 指令（artex 的角色切换点）。"""
        client = FakeClient([
            [("graph", {"op": "add_intent", "family": "lfi", "target": "x",
                        "why": "探路"}),
             ("graph", {"op": "close_intent", "intent_id": 1, "status": "dead",
                        "verdict": "无差异"})],
            [("finish", {"summary": "done"})],
        ])
        solve_challenge(make_challenge(), StartResult("t-001", ["127.0.0.1:1"]),
                        client, deadline=time.time() + 30, max_steps=4)
        second_turn_messages = client.hist[1]
        last = second_turn_messages[-1]
        text = "".join(b.get("text", "") for b in last["content"]
                       if isinstance(b, dict))
        self.assertIn("planner 指令", text, "收口后没有切换到 planner 角色")

    def test_unknown_tool_does_not_kill_loop(self):
        client = FakeClient([
            [("bogus_tool", {"x": 1})],
            [("finish", {"summary": "done"})],
        ])
        solve_challenge(make_challenge(), StartResult("t-001", ["127.0.0.1:1"]),
                        client, deadline=time.time() + 30, max_steps=4)
        self.assertEqual(client.calls, 2, "未知工具应该报错字符串而不是打断循环")

    def test_seed_message_carries_recon(self):
        """开局消息必须把侦察结果和图状态带给模型（状态外置的读回路径）。"""
        with _Server() as srv:
            client = FakeClient([[("finish", {"summary": "done"})]])
            solve_challenge(
                make_challenge(), StartResult("t-001", [f"127.0.0.1:{srv.port}"]),
                client, deadline=time.time() + 60, max_steps=3)
        seed = client.hist[0][0]["content"]
        self.assertIn("侦察", seed)
        self.assertTrue(client.system_prompts[0].startswith("你是授权 CTF 靶场"))

    def test_gc_archives_old_outputs(self):
        """老 tool_result 超长要归档；关键结论在 notes/图/证据里。"""
        client = FakeClient([
            [("shell", {"command": "python3 -c \"print('A'*5000)\""})],
        ] + [[("shell", {"command": f"echo fill{i}"})] for i in range(9)]
            + [[("finish", {"summary": "done"})]])
        solve_challenge(make_challenge(), StartResult("t-001", ["127.0.0.1:1"]),
                        client, deadline=time.time() + 120, max_steps=15)
        # 第 2 次调用时的最后一条消息才是第 1 轮的 tool_result（第 1 次调用时
        # 对话里只有种子消息）
        first_results = client.hist[1][-1]["content"]
        big = [b for b in first_results
               if isinstance(b, dict) and b.get("type") == "tool_result"]
        self.assertTrue(big)
        self.assertTrue(any("已归档" in str(b.get("content", "")) for b in big),
                         "超长输出没有被 GC 归档")


if __name__ == "__main__":
    unittest.main()
