"""图驱动的端到端回归测试（不依赖平台）。

造一个和 a-05 同构的假靶标：
    /login.php      → 登录表单（username / password）
    /dashboard.php  → 需要会话，里面有 /download.php?id=CONTRACT-2024-001.pdf
    /download.php   → 需要会话，id 带 ../ 或含 flag 时回文件内容

然后跑真实的 solve_challenge，断言：
1. flag 被提交；
2. 步数极少（模型不参与也能推完）；
3. **LLM 只被问了一次**——决策确实被图接管了。

第 3 条是关键：旧实现每步都问模型，模型就会在「已经拿到 file_read 却回头
枚举 admin 接口」上打转。图驱动之后，模型的调用次数应该塌到个位数。
"""
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from deepsick_attack.bench_client import Challenge, StartResult
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


class _FakeLLM:
    """只会执行固定动作的假模型。它不该是解题主力——主力是图。"""

    def __init__(self, port: int):
        self.calls = 0
        self.script = (
            f'{{"cmd": "curl -sS -m 8 http://127.0.0.1:{port}/login.php"}}',
        )

    def complete(self, system, messages=None):
        self.calls += 1
        return {"text": self.script[0]}


class GraphDrivenSolverTest(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), _AssetHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_solves_login_then_lfi_without_asking_model_repeatedly(self):
        submitted: list[str] = []
        llm = _FakeLLM(self.port)
        challenge = Challenge(
            unique_code="t-graph", description="资产管理系统", difficulty="easy",
            level=1, total_score=100, flag_count=1, correct_flag_count=0,
            is_completed=False, container_status="running",
            container_addr=[f"127.0.0.1:{self.port}"],
        )
        started = StartResult("t-graph", [f"127.0.0.1:{self.port}"])

        flags = solve_challenge(
            challenge, started, llm,
            deadline=__import__("time").time() + 120,
            max_steps=12,
            submit=lambda f: (submitted.append(f), type("R", (), {"correct": True})())[1],
        )

        self.assertTrue(any(FLAG in f for f in submitted),
                        f"没有提交 flag，实际提交={submitted}")
        # 模型不该是解题主力：它只该负责第一条「去看看登录页」
        self.assertLessEqual(llm.calls, 3,
                             f"模型被问了 {llm.calls} 次，说明决策没被图接管")
        self.assertTrue(flags)


if __name__ == "__main__":
    unittest.main()
