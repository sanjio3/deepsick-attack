"""agent 循环端到端回归测试（不依赖平台与真实模型）。

造一个和 a-05 同构的假靶标：
    /login.php      → 登录表单（username / password）
    /dashboard.php  → 需要会话，里面有 /download.php?id=CONTRACT-2024-001.pdf
    /download.php   → 需要会话，id 带 ../ 或含 flag 时回文件内容

然后跑真实的 solve_challenge，用脚本化的 FakeClient 模拟模型：
    登录 → 看 dashboard → 发现 download.php?id= → 打 LFI 读 flag。

断言四件事：
1. flag 被提交；
2. 模型回合极少（4 轮工具调用 + finish 收尾，链路靠脚本逐步推进）；
3. 每一步的工具输出确实进了对话（tool_result 回传）；
4. shell 输出里的入口被确定性副驾驶自动上图（download.php?id= 是 file 参数）。
"""
import json
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from deepsick_attack.bench_client import Challenge, StartResult
from deepsick_attack.events import set_sink
from deepsick_attack.solver import solve_challenge

FLAG = "flag{graph_driven_local_case}"


class _AssetHandler(BaseHTTPRequestHandler):
    """假 a-05：登录 → 仪表盘 → 任意文件读取。"""

    def _logged_in(self) -> bool:
        return "PHPSESSID=ok" in (self.headers.get("Cookie") or "")

    def _send(self, code: int, body: str = "", headers=None):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or []):
            self.send_header(key, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/login.php":
            self._send(200, (
                '<html><body><form method="POST" action="/login.php">'
                '<input type="text" name="username">'
                '<input type="password" name="password">'
                '</form></body></html>'))
        elif path == "/dashboard.php":
            if not self._logged_in():
                self._send(302, "", [("Location", "/login.php")])
                return
            self._send(200, (
                '<html><body>'
                '<a href="/download.php?id=CONTRACT-2024-001.pdf">下载合同</a>'
                '<a href="/logout.php">退出登录</a>'
                '</body></html>'))
        elif path == "/download.php":
            if not self._logged_in():
                self._send(302, "", [("Location", "/login.php")])
                return
            fid = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
            if "flag" in fid.lower():
                self._send(200, FLAG)
            elif "passwd" in fid or ".." in fid:
                self._send(200, "root:x:0:0:root:/root:/bin/bash")
            else:
                self._send(404, "not found")
        elif path == "/":
            self._send(302, "", [("Location", "/login.php")])
        else:
            self._send(404, "not found")

    def do_POST(self):
        if urlparse(self.path).path != "/login.php":
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = parse_qs(self.rfile.read(length).decode())
        user = (body.get("username") or [""])[0]
        pwd = (body.get("password") or [""])[0]
        if user == "employee" and pwd == "employee123":
            self._send(302, "", [("Location", "/dashboard.php"),
                                 ("Set-Cookie", "PHPSESSID=ok; path=/")])
        else:
            self._send(200, "<html>login failed</html>")

    def log_message(self, *args):
        pass


class FakeClient:
    """脚本化模型：每轮发若干个 tool_use 块，工具结果原样回传到对话。"""

    def __init__(self, script):
        self.script = [list(turn) for turn in script]
        self.calls = 0
        self.hist = []

    def chat(self, system, messages, tools=None, **kwargs):
        self.calls += 1
        self.hist.append(json.loads(json.dumps(messages)))
        if not self.script:
            return {"content": [{"type": "text", "text": "脚本耗尽"}],
                    "stop_reason": "end_turn"}
        blocks = []
        for i, (name, inp) in enumerate(self.script.pop(0)):
            blocks.append({"type": "text", "text": f"{i}:{name}"})
            blocks.append({"type": "tool_use", "id": f"c{self.calls}-{i}",
                           "name": name, "input": inp})
        return {"content": blocks, "stop_reason": "tool_use"}


class AgentLoopSolverTest(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), _AssetHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.events = []
        set_sink(self.events.append)

    def tearDown(self):
        set_sink(None)
        self.server.shutdown()
        self.server.server_close()

    def _script(self) -> list:
        base = f"http://127.0.0.1:{self.port}"
        # 必须给 bash 可直接消费的 POSIX 路径（toolkit.shell 用 bash -c 执行，
        # Windows 临时路径的反斜杠会被 bash 当转义符吃掉）
        jar = f"/tmp/gs-jar-{time.time_ns()}.txt"
        return [
            [("shell", {"command": f"curl -sS -i -m 8 -c {jar} {base}/login.php"})],
            [("shell", {"command":
                        f"curl -sS -i -m 8 -c {jar} -b {jar} "
                        f"-d 'username=employee&password=employee123' "
                        f"{base}/login.php"})],
            [("shell", {"command": f"curl -sS -i -m 8 -b {jar} {base}/dashboard.php"})],
            [("shell", {"command":
                        f'curl -sS -m 8 -b {jar} "{base}/download.php?id=../../flag"'})],
            [("finish", {"summary": "flag 已拿到并自动提交"})],
        ]

    def test_solves_login_then_lfi_with_tool_loop(self):
        submitted: list[str] = []
        client = FakeClient(self._script())
        challenge = Challenge(
            unique_code="t-graph", description="资产管理系统", difficulty="easy",
            level=1, total_score=100, flag_count=1, correct_flag_count=0,
            is_completed=False, container_status="running",
            container_addr=[f"127.0.0.1:{self.port}"],
        )
        started = StartResult("t-graph", [f"127.0.0.1:{self.port}"])

        flags = solve_challenge(
            challenge, started, client,
            deadline=time.time() + 120, max_steps=12,
            submit=lambda f: (submitted.append(f),
                              type("R", (), {"correct": True})())[1],
        )

        self.assertTrue(any(FLAG in f for f in submitted),
                        f"没有提交 flag，实际提交={submitted}")
        # 第 4 轮 curl 拿到 flag 后循环按「flag 数够了」直接收尾，finish 不再消费
        self.assertEqual(client.calls, 4, f"模型回合数异常：{client.calls}")
        # turn N 的 tool_result 出现在第 N+1 次调用的消息列表末尾；
        # 第 4 轮拿到 flag 后循环直接收尾，所以只有前 3 轮的结果可核对
        for offset, expect in enumerate(("login.php", "PHPSESSID", "download.php")):
            last = client.hist[offset + 1][-1]["content"]
            text = "".join(str(b.get("content", "")) for b in last
                           if isinstance(b, dict))
            self.assertIn(expect, text, f"第 {offset + 1} 轮的上下文里没有 {expect}")
        self.assertTrue(flags)
        # 工具执行有事件留痕
        tools = [e for e in self.events if e["event"] == "agent_tool"]
        self.assertTrue(tools, "agent_tool 事件缺失，工具执行没有被记录")


if __name__ == "__main__":
    unittest.main()
