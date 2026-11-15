"""真实靶标解题器：代码负责感知与判定，模型只负责在候选里做选择。

设计依据（这一版是重写，不是调参）：

1. 感知层（sense.py）——平台给的 container_addr 只是线索，不是攻击面。同一台
   宿主机上映射着多道题的不同端口，给了 `:22` 不代表这题只有 SSH。所以开场由
   代码自己扫端口、抓 banner、判协议、问 mDNS，不经过模型。
2. 事实板（facts.py）——观测压缩成结构化事实并落盘，prompt 里给事实摘要而不是
   最近 8 条原文。原来 1800 字符一截断，第 3 步发现的东西第 10 步就丢了。
3. 候选意图（playbook.py）——模型不再在无限动作空间里自由编 JSON，而是从代码
   生成的 4-8 条候选里挑一条。Flash 级模型只能做「N 选 1」，做不了搜索。
4. 探测器（playbook.detect）——是否出 flag、是否触发告警、是否「太配合」，
   全部由代码吃真实字节判定，模型自述不参与。
5. 实时提交——一旦判定出候选立刻交给平台，用平台返回的 correct/进度当反馈，
   而不是攒到本题结束再一次性提交。

凭据只从环境变量读取；所有输出来自 events.emit，不打印任何密钥。
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import sense
from .bench_client import Challenge, StartResult
from .events import emit
from .facts import Fact, FactBoard
from .flags import extract_flags  # noqa: F401  - 对外兼容旧的 import 路径
from .playbook import Candidate, detect, propose

MAX_OBS_CHARS = 2600
MAX_STEPS_HARD_CAP = 60
MAX_FLAGS_PER_CHALLENGE = 15
# 同一主机两次动作之间的最小间隔。主动防御/蜜罐类靶标对高频请求敏感，
# 打得太急会被判定为扫描器，触发死手这类自毁机制。
MIN_ACTION_GAP = 0.9
BANNER_CLIP = 700

SSH_CREDS = [
    ("root", "root"), ("root", "toor"), ("root", "password"), ("admin", "admin"),
    ("ubuntu", "ubuntu"), ("vagrant", "vagrant"), ("test", "test"),
    ("msfadmin", "msfadmin"), ("user", "user"), ("guest", "guest"),
]

SYSTEM_PROMPT = """你是一个在隔离沙箱里运行的授权 CTF 解题智能体。目标是从靶标拿到 Flag。

每一轮你必须输出**一个 JSON 对象**，不要输出解释性文字。三种形式：

1. 从候选里挑一个（推荐，绝大多数情况用这个）：
{"pick": "候选 id", "thought": "为什么选它"}
2. 自己写一个动作：
{"tool": "工具名", "args": {...}, "thought": "为什么"}
3. 已经拿到 flag，交卷：
{"flags": ["flag 字符串"], "thought": "从哪里拿到的"}

工具清单（自定义动作时用）：
- http_request {"method":"GET","path":"/x","headers":{},"body":""}  path 可写完整 URL
- http_get {"path":"/x"} / http_post {"path":"/x","body":"a=1"}
- port_scan {"ports":[80,443]}  扫指定端口
- tcp_send {"port":6379,"payload":"PING\\r\\n"}
- shell {"command":"curl -s http://127.0.0.1/"}  在沙箱内执行
- decode {"value":"...","kind":"base64|hex|url|rot13"}
- ssh_audit {"port":22}  读 SSH 版本与允许的认证方式
- ssh_login {"port":22,"creds":["user:pass"]}  逐个试登录并自动找 flag 文件（最多 4 组）
- dns_query {"name":"example.com","qtype":"TXT"}
- udp_probe {"port":5353,"payload_hex":"0000"}  原始 UDP 收发
- mdns {}  列出 mDNS 公布的服务
- rescan {}  重新扫端口并抓 banner

判断规则：
- 优先挑候选，除非候选都不合适。候选是代码根据当前事实生成的，比自由发挥靠谱。
- 标记 risk=high 的候选说明该服务可能带主动防御，只在没有别的路时才碰。
- 响应「太配合」（一次请求就给 root、目录整齐得反常）通常是蜜罐，别深挖，换条路。
- 看到形如 xxx{...} 的可疑串就立刻交卷，不要等确认——平台会给对错反馈。
- 同一个动作不要重复做，做了也没用。"""


@dataclass
class Observation:
    step: int
    tool: str
    args: dict
    output: str
    elapsed: float
    thought: str = ""


@dataclass
class SolveContext:
    host: str
    hint_ports: list[int] = field(default_factory=list)
    base_url: str = ""
    board: FactBoard | None = None
    observations: list[Observation] = field(default_factory=list)
    jar: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)


def parse_targets(container_addr: list[str]) -> tuple[str, list[int]]:
    """只解析出主机与提示端口。**不**再臆造 base_url。

    旧实现把第一个地址拼成 `http://host:port` 当 base_url，于是只给了 `:22` 的
    题会变成「往 SSH 端口发 HTTP」，整题 40 步全是失败请求。现在协议由 banner
    决定，地址只当线索。
    """
    host = ""
    ports: list[int] = []
    for addr in container_addr or []:
        addr = str(addr).strip()
        if not addr:
            continue
        candidate = addr if "://" in addr else "http://" + addr
        try:
            parts = urllib.parse.urlsplit(candidate)
        except ValueError:
            continue
        if not parts.hostname:
            continue
        if not host:
            host = parts.hostname
        if parts.port and parts.port not in ports:
            ports.append(parts.port)
    return host, ports


class Toolkit:
    """固定工具集。每个方法返回给模型看的文本观测。"""

    def __init__(self, context: SolveContext, shell_timeout: int = 30,
                 http_timeout: int = 12):
        self.context = context
        self.shell_timeout = shell_timeout
        self.http_timeout = http_timeout
        # 打靶流量必须直连：环境里的出网代理会把发往靶标的请求也劫持成 502
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(context.jar),
        )
        self._env_opener = None
        self._last_action = 0.0

    # -- 内部 ------------------------------------------------------

    def pace(self) -> None:
        gap = time.time() - self._last_action
        if gap < MIN_ACTION_GAP:
            time.sleep(MIN_ACTION_GAP - gap)
        self._last_action = time.time()

    def _absolute(self, path: str) -> str:
        path = str(path or "/").strip()
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        base = self.context.base_url or f"http://{self.context.host}"
        return base.rstrip("/") + path

    @staticmethod
    def _clip(text: str, limit: int = MAX_OBS_CHARS) -> str:
        text = text if isinstance(text, str) else str(text)
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n...[截断，共 {len(text)} 字符]"

    # -- HTTP ------------------------------------------------------

    def http_request(self, method: str = "GET", path: str = "/",
                     headers: dict | None = None, body: str = "") -> str:
        url = self._absolute(path)
        data = body.encode("utf-8") if body else None
        verb = str(method or "GET").upper()
        hdrs = {str(k): str(v) for k, v in (headers or {}).items()}

        def send(opener) -> str:
            request = urllib.request.Request(url, data=data, method=verb,
                                             headers=hdrs)
            with opener.open(request, timeout=self.http_timeout) as response:
                text = response.read().decode("utf-8", errors="replace")
                head = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
                return self._clip(f"HTTP {response.status} {url}\n{head}\n\n{text}")

        self.pace()
        try:
            return send(self._opener)
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            head = "\n".join(f"{k}: {v}" for k, v in exc.headers.items())
            return self._clip(f"HTTP {exc.code} {url}\n{head}\n\n{text}")
        except Exception as exc:  # 网络层失败也算观测
            alt = self._env_proxy_opener()
            if alt is not None:
                try:
                    return "[直连失败，已改走环境代理]\n" + send(alt)
                except Exception:
                    pass
            return f"请求失败 {url}: {type(exc).__name__}: {exc}"

    def _env_proxy_opener(self):
        if self._env_opener is False:
            return None
        if self._env_opener is None:
            proxies = urllib.request.getproxies()
            if not proxies:
                self._env_opener = False
                return None
            self._env_opener = urllib.request.build_opener(
                urllib.request.ProxyHandler(proxies),
                urllib.request.HTTPCookieProcessor(self.context.jar),
            )
        return self._env_opener

    def http_get(self, path: str = "/", headers: dict | None = None) -> str:
        return self.http_request("GET", path, headers)

    def http_post(self, path: str = "/", body: str = "",
                  content_type: str = "application/x-www-form-urlencoded") -> str:
        return self.http_request("POST", path, {"Content-Type": content_type}, body)

    # -- 网络 ------------------------------------------------------

    def port_scan(self, ports: list | None = None) -> str:
        host = self.context.host
        if not host:
            return "没有可用主机地址"
        targets = []
        for raw in (ports or self.context.hint_ports):
            try:
                targets.append(int(raw))
            except (TypeError, ValueError):
                continue
        targets = targets or sense.TOP_PORTS
        open_ports = sense.scan(host, targets[:1024])
        return f"主机 {host} 指定端口中的开放端口: {open_ports}"

    def rescan(self) -> str:
        """深度重扫：提示端口邻域没东西时，才升级到全量端口表。"""
        return (recon_scan(self.context, self.context.board,
                           emit_events=False, deep=True)
                or "重扫完成，无新增服务")

    def tcp_send(self, port: int, payload: str = "", read_bytes: int = 4096) -> str:
        host = self.context.host
        if not host:
            return "没有可用主机地址"
        try:
            port = int(port)
        except (TypeError, ValueError):
            return "port 必须是整数"
        data = payload.encode("utf-8", errors="replace") if payload else b""
        self.pace()
        try:
            with socket.create_connection((host, port),
                                          timeout=self.http_timeout) as sock:
                if data:
                    sock.sendall(data)
                sock.settimeout(self.http_timeout)
                chunks, total = [], 0
                while total < int(read_bytes or 4096):
                    try:
                        chunk = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                text = b"".join(chunks).decode("utf-8", errors="replace")
                return self._clip(f"TCP {port} 收到 {total} 字节:\n{text}")
        except Exception as exc:
            return f"TCP {port} 失败: {type(exc).__name__}: {exc}"

    def udp_probe(self, port: int = 5353, payload_hex: str = "0000") -> str:
        host = self.context.host
        try:
            payload = bytes.fromhex(str(payload_hex))
        except ValueError:
            payload = b"\x00"
        data = sense.udp_probe(host, int(port), payload)
        return (f"UDP {port} 收到 {len(data)} 字节：{data[:400]!r}"
                if data else f"UDP {port} 无响应")

    def mdns(self) -> str:
        names = sense.mdns_services()
        if not names:
            return "mDNS 没有公布任何服务（可能未启用或不在同一广播域）"
        return "mDNS 公布的服务：\n" + "\n".join(names)

    def dns_query(self, name: str = "", qtype: str = "TXT",
                  server: str | None = None) -> str:
        if not name:
            return "name 为空"
        return sense.dns_query(name, qtype, server)

    # -- SSH -------------------------------------------------------

    def ssh_audit(self, port: int = 22) -> str:
        host = self.context.host
        try:
            import paramiko  # type: ignore
        except ImportError:
            return "paramiko 不可用（镜像未带 vendor 依赖），无法做 SSH 审计"
        self.pace()
        try:
            transport = paramiko.Transport((host, int(port)))
            transport.banner_timeout = 6
            transport.start_client(timeout=8)
            remote = transport.remote_version
            auth = []
            try:
                transport.auth_none("probe")
            except paramiko.BadAuthenticationType as exc:
                auth = list(exc.allowed_types or [])
            except Exception:  # noqa: BLE001
                pass
            transport.close()
            return (f"SSH 服务 {host}:{port}\n版本: {remote}\n"
                    f"允许的认证方式: {auth or '未知（可能需要先提供用户名）'}")
        except Exception as exc:  # noqa: BLE001
            return f"SSH 审计失败 {host}:{port}: {type(exc).__name__}: {exc}"

    def ssh_login(self, port: int = 22, creds: list | None = None) -> str:
        """只在题目明确需要时用，且最多试 4 组——爆破最容易触发主动防御。"""
        host = self.context.host
        try:
            import paramiko  # type: ignore
        except ImportError:
            return "paramiko 不可用（镜像未带 vendor 依赖），无法尝试 SSH 登录"
        pairs: list[tuple[str, str]] = []
        for item in creds or []:
            text = str(item)
            if ":" in text:
                user, _, pwd = text.partition(":")
                pairs.append((user, pwd))
        for pair in SSH_CREDS:
            if pair not in pairs:
                pairs.append(pair)
        pairs = pairs[:4]

        for user, pwd in pairs:
            self.pace()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(host, port=int(port), username=user, password=pwd,
                               timeout=8, banner_timeout=8, auth_timeout=8,
                               allow_agent=False, look_for_keys=False)
            except Exception as exc:  # noqa: BLE001
                emit("ssh_auth_fail", port=port, user=user,
                     detail=type(exc).__name__)
                continue
            try:
                out = self._ssh_collect(client)
                return (f"SSH 登录成功 {user}:{pwd} @ {host}:{port}\n{out}")
            finally:
                client.close()
        return f"SSH {host}:{port} 试了 {len(pairs)} 组常见口令均失败（已停止，避免触发防御）"

    def _ssh_collect(self, client) -> str:
        commands = [
            "id; uname -a; hostname",
            "ls -la / /root /home 2>/dev/null",
            "cat /flag /flag.txt /root/flag /root/flag.txt 2>/dev/null",
            "grep -rIl --exclude-dir=proc --exclude-dir=sys -m1 flag / 2>/dev/null | head -20",
        ]
        chunks = []
        for command in commands:
            try:
                _, stdout, stderr = client.exec_command(command, timeout=20)
                text = stdout.read().decode("utf-8", "replace")
                err = stderr.read().decode("utf-8", "replace")
                chunks.append(f"$ {command}\n{text}{err}"[:1500])
            except Exception as exc:  # noqa: BLE001
                chunks.append(f"$ {command}\n(执行失败 {type(exc).__name__})")
        return self._clip("\n\n".join(chunks))

    # -- 沙箱 ------------------------------------------------------

    def shell(self, command: str) -> str:
        command = str(command or "").strip()
        if not command:
            return "command 为空"
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        self.pace()
        try:
            completed = subprocess.run(
                ["bash", "-lc", command], capture_output=True,
                timeout=self.shell_timeout, cwd="/tmp", text=True,
                errors="replace", env=env,
            )
        except subprocess.TimeoutExpired:
            return f"命令超时（>{self.shell_timeout}s）：{command}"
        except Exception as exc:
            return f"命令执行失败: {type(exc).__name__}: {exc}"
        out = (completed.stdout or "") + (completed.stderr or "")
        return self._clip(f"exit={completed.returncode}\n{out or '(无输出)'}")

    def decode(self, value: str = "", kind: str = "base64") -> str:
        import base64
        import binascii
        raw = str(value or "")
        kind = str(kind or "base64").lower()
        try:
            if kind == "base64":
                padded = raw + "=" * (-len(raw) % 4)
                return base64.b64decode(padded).decode("utf-8", errors="replace")
            if kind == "hex":
                return binascii.unhexlify(raw).decode("utf-8", errors="replace")
            if kind == "url":
                return urllib.parse.unquote(raw)
            if kind == "rot13":
                import codecs
                return codecs.decode(raw, "rot13")
            return f"不支持的 kind: {kind}"
        except Exception as exc:
            return f"解码失败: {type(exc).__name__}: {exc}"

    ALLOWED = {
        "http_request": "http_request", "http_get": "http_get",
        "http_post": "http_post", "port_scan": "port_scan",
        "tcp_send": "tcp_send", "shell": "shell", "decode": "decode",
        "ssh_audit": "ssh_audit", "ssh_login": "ssh_login",
        "dns_query": "dns_query", "udp_probe": "udp_probe",
        "mdns": "mdns", "rescan": "rescan",
    }

    def run(self, tool: str, args: dict) -> str:
        name = self.ALLOWED.get(str(tool))
        if name is None:
            return f"未知工具 {tool!r}，可用：{sorted(self.ALLOWED)}"
        args = args if isinstance(args, dict) else {}
        try:
            return getattr(self, name)(**args)
        except TypeError as exc:
            return f"参数不匹配 {tool}: {exc}"
        except Exception as exc:
            return f"工具 {tool} 执行异常: {type(exc).__name__}: {exc}"


def recon_scan(context: SolveContext, board: FactBoard,
               emit_events: bool = True, deep: bool = False) -> str:
    """代码驱动的开场侦察：扫端口 → 抓 banner → 判协议 → 落事实。

    这一步不经过模型。它是「看清门在哪、是什么锁」的动作，与模型能力无关，
    却是旧实现里完全缺失的一环。

    默认只扫提示端口及其邻域：平台给的地址只是线索，同一宿主机 IP 上挂着多道题
    的不同端口，扫全端口会把 agent 引去攻击别的题的容器。`deep=True` 才升级到
    全量端口表（模型发现该扫的地方没东西时会主动调 rescan）。
    """
    host = context.host
    if not host:
        return ""
    ports = sense.expand_ports(context.hint_ports, deep=deep)
    started = time.time()
    open_ports = sense.scan(host, ports)
    if emit_events:
        emit("recon_scan", host=host, scanned=len(ports), open=len(open_ports),
             deep=deep, elapsed=round(time.time() - started, 1))

    lines = [f"扫描 {len(ports)} 个端口，开放 {len(open_ports)} 个: {open_ports}"]
    protos: dict[int, str] = {}
    for port in open_ports:
        info = sense.fingerprint(host, port)
        proto = info.get("proto") or "unknown"
        protos[port] = proto
        detail = f"{host}:{port} {proto}"
        banner = (info.get("banner") or "").replace("\n", " ")[:120]
        if banner:
            detail += f' "{banner}"'
        board.add(Fact("service", f"{host}:{port}", detail, "low"))
        lines.append(f"  {port}: {proto} {banner[:90]}")

    # 入口选择：优先用平台给的提示端口，不用「碰到的第一个 http 服务」。
    # 共享宿主机上这个顺序差异会直接决定 agent 打的是不是本题。
    if not context.base_url:
        context.base_url = _choose_base_url(host, protos, context.hint_ports)
        if context.base_url:
            board.add(Fact("service", f"base_url:{context.base_url}",
                           f"默认 Web 入口 {context.base_url}", "low"))

    # mDNS：动态靶标常用它公布真实端点
    if 5353 in open_ports or not open_ports:
        names = sense.mdns_services()
        if names:
            lines.append("mDNS 公布: " + ", ".join(names[:8]))
            for name in names[:8]:
                board.add(Fact("artifact", f"mdns:{name}", f"mDNS 服务 {name}",
                               "low"))
    return "\n".join(lines)


def _choose_base_url(host: str, protos: dict[int, str],
                     hint_ports: list[int]) -> str:
    """挑一个 Web 入口。以 fingerprint 判出的协议为准，提示端口优先。

    不能按端口号猜：靶标常用 30000+ 的随机端口跑 HTTP，也常在 5432 上放
    非 Postgres 的东西。
    """
    web = [port for port, proto in protos.items() if proto == "https"]
    plain = [port for port, proto in protos.items() if proto == "http"]
    if not web and not plain:
        return ""
    for port in hint_ports:
        if port in plain:
            return f"http://{host}:{port}"
        if port in web:
            return f"https://{host}:{port}"
    if plain:
        return f"http://{host}:{plain[0]}"
    return f"https://{host}:{web[0]}"


def _build_pick_prompt(challenge: Challenge, context: SolveContext) -> str:
    board = context.board
    candidates = propose(board)
    lines = [
        "## 题目",
        f"编号: {challenge.unique_code}  难度: {challenge.difficulty or '未知'} "
        f"分值: {challenge.total_score}  Flag 数量: {challenge.flag_count}",
        "",
        "## 题面",
        challenge.description.strip() or "（平台未给出题面，只能靠主动侦察）",
        "",
        "## 事实板（代码已核实的观测结论）",
        board.snapshot() if board else "（空）",
        "",
        "## 可选动作",
    ]
    if candidates:
        lines += [item.line() for item in candidates]
    else:
        lines.append("- 没有可用候选，请自己写动作")
    recent = context.observations[-3:]
    if recent:
        lines += ["", "## 最近几步原始观测"]
        for obs in recent:
            body = obs.output
            if len(body) > 900:
                body = body[:900] + "..."
            lines.append(f"### 第 {obs.step} 步 {obs.tool}({json.dumps(obs.args, ensure_ascii=False)[:120]})\n{body}")
    lines += ["", "输出一个 JSON 对象。优先 pick 候选。"]
    return "\n".join(lines)


def _extract_json_object(text: str) -> dict | None:
    """从模型回复里取出第一个 JSON 对象，容忍前后包裹的文字。"""
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass
    depth, start = 0, -1
    for idx, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    payload = json.loads(text[start:idx + 1])
                except json.JSONDecodeError:
                    start = -1
                    continue
                if isinstance(payload, dict):
                    return payload
                start = -1
    return None


def solve_challenge(challenge: Challenge, started: StartResult, client, *,
                    deadline: float | None = None, max_steps: int | None = None,
                    shell_timeout: int = 30,
                    submit: Callable[[str], Any] | None = None) -> list[str]:
    """跑单道题。返回已提交（或已收集）的 Flag 列表。

    submit 由调用方注入（把 flag 交给平台并返回结果），有它就能拿到平台反馈，
    没有就只在本地收集，供离线测试使用。
    """
    host, hint_ports = parse_targets(started.container_addr)
    if not host:
        emit("solve_no_target", unique_code=challenge.unique_code,
             container_addr=started.container_addr,
             note="平台未返回可用靶标地址")
        return []

    board = FactBoard(host=host)
    context = SolveContext(host=host, hint_ports=hint_ports, board=board)
    toolkit = Toolkit(context, shell_timeout=shell_timeout)
    steps = max_steps or int(os.environ.get("BENCH_MAX_STEPS", "40"))
    steps = max(1, min(steps, MAX_STEPS_HARD_CAP))
    if deadline is None:
        deadline = time.time() + int(os.environ.get("BENCH_CHALLENGE_SECONDS", "780"))

    emit("solve_begin", unique_code=challenge.unique_code, host=host,
         hint_ports=hint_ports, max_steps=steps,
         budget_seconds=int(deadline - time.time()))

    verified: list[str] = []
    seen: set[str] = set()

    def submit_flag(flag: str, step: int, source: str) -> bool:
        key = flag.lower()
        if key in seen or len(verified) >= MAX_FLAGS_PER_CHALLENGE:
            return False
        seen.add(key)
        verified.append(flag)
        board.add(Fact("flag", f"flag:{key}", f"候选 Flag {flag[:80]}", "low", step))
        if submit is None:
            emit("solve_flag_found", unique_code=challenge.unique_code, step=step,
                 flag=flag, source=source)
            return True
        try:
            result = submit(flag)
        except Exception as exc:  # noqa: BLE001
            emit("solve_submit_error", unique_code=challenge.unique_code, step=step,
                 detail=f"{type(exc).__name__}: {exc}"[:160])
            return True
        correct = bool(getattr(result, "correct", False))
        emit("solve_submit", unique_code=challenge.unique_code, step=step,
             flag=flag[:100], correct=correct, source=source,
             progress=f"{getattr(result, 'correct_flag_count', '?')}/"
                      f"{getattr(result, 'total_flag_count', '?')}")
        return correct

    # ---- 阶段一：代码侦察（不经过模型）----
    recon_text = recon_scan(context, board)
    context.observations.append(
        Observation(0, "recon", {"host": host, "hint_ports": hint_ports},
                    recon_text, 0.0, "开场侦察由代码完成"))
    for flag in extract_flags(recon_text):
        submit_flag(flag, 0, "侦察响应提取")
    if board.stats()["services"] == 0:
        emit("solve_blind", unique_code=challenge.unique_code,
             note="端口扫描未发现任何服务，本题可能不可达")

    # ---- 阶段二：候选意图循环 ----
    last_tool = ""
    repeat = 0
    for step in range(1, steps + 1):
        if time.time() >= deadline:
            emit("solve_timeout", unique_code=challenge.unique_code, step=step)
            break
        if len(verified) >= max(1, challenge.flag_count or 1):
            break

        prompt = _build_pick_prompt(challenge, context)
        started_at = time.time()
        try:
            reply = client.complete(SYSTEM_PROMPT,
                                    messages=[{"role": "user", "content": prompt}])
        except Exception as exc:  # noqa: BLE001
            emit("solve_llm_error", unique_code=challenge.unique_code, step=step,
                 detail=f"{type(exc).__name__}: {exc}"[:200])
            break
        text = reply.get("text") or ""
        action = _extract_json_object(text)
        if not action:
            emit("solve_bad_action", unique_code=challenge.unique_code, step=step,
                 raw=text[:200])
            continue

        thought = str(action.get("thought") or "")[:300]

        # 交卷：疑似即提交，不等确认
        if "flags" in action and "pick" not in action and "tool" not in action:
            claimed = [str(f).strip() for f in (action.get("flags") or [])
                       if str(f).strip()]
            if not claimed:
                context.observations.append(Observation(
                    step, "(没收工)", {}, "你还没交任何 flag。若确实拿不到，"
                    "继续换候选；不要输出空 flags。", time.time() - started_at))
                continue
            for flag in claimed:
                submit_flag(flag, step, "模型声明")
            emit("solve_final", unique_code=challenge.unique_code, step=step,
                 thought=thought, verified=len(verified))
            break

        # 挑候选
        candidate: Candidate | None = None
        if action.get("pick"):
            pick = str(action["pick"])
            candidate = next((c for c in propose(board, 12) if c.id == pick), None)
            if candidate is None:
                emit("solve_bad_pick", unique_code=challenge.unique_code,
                     step=step, pick=pick)
                context.observations.append(Observation(
                    step, "(无效候选)", {}, f"候选 {pick} 不存在或已试过，"
                    "请从当前列表里挑一个。", time.time() - started_at))
                continue
            tool, args = candidate.tool, candidate.args
            board.mark_tried(candidate.id)
        else:
            tool = str(action.get("tool") or "")
            args = action.get("args") or {}

        if tool == "custom":
            context.observations.append(Observation(
                step, "(要求自定义)", {}, "请直接输出 {\"tool\":...,\"args\":{...}}。",
                time.time() - started_at))
            continue

        output = toolkit.run(tool, args if isinstance(args, dict) else {})
        elapsed = time.time() - started_at
        context.observations.append(
            Observation(step, tool, args if isinstance(args, dict) else {},
                        output, elapsed, thought))
        emit("solve_step", unique_code=challenge.unique_code, step=step, tool=tool,
             thought=thought, args=json.dumps(args, ensure_ascii=False)[:200],
             output=output[:400], elapsed=round(elapsed, 2),
             facts=board.stats()["facts"])

        probe = detect(output)
        for flag in probe.flags:
            submit_flag(flag, step, f"{tool} 响应提取")
        if probe.tripwire:
            board.flag_honeypot(f"{host}:{args.get('port', '')}".rstrip(":"))
            emit("solve_tripwire", unique_code=challenge.unique_code, step=step,
                 marker=probe.tripwire, tool=tool)
        if probe.too_easy:
            emit("solve_too_easy", unique_code=challenge.unique_code, step=step,
                 marker=probe.too_easy, note="响应过于配合，疑似蜜罐")

        # 重复动作检测：连续三次一样就强制换路
        signature = f"{tool}:{json.dumps(args, sort_keys=True, ensure_ascii=False)}"
        repeat = repeat + 1 if signature == last_tool else 1
        last_tool = signature
        if repeat >= 3:
            emit("solve_loop_guard", unique_code=challenge.unique_code, step=step,
                 tool=tool)
            repeat = 0
            board.mark_tried(f"{tool}:{step}", ok=False)

    emit("solve_done", unique_code=challenge.unique_code,
         steps=len(context.observations), flags=len(verified),
         **board.stats())
    return verified


def make_llm_solver(*, max_steps: int | None = None,
                    total_seconds: int | None = None,
                    shell_timeout: int = 30) -> Callable[..., list[str]]:
    """构造解题器。第三个参数 submit 由 run_benchmark 注入，用于实时提交。"""
    from .llm import MiniMaxClient, get_config

    client = MiniMaxClient(get_config())
    total = total_seconds or int(os.environ.get("BENCH_TOTAL_SECONDS", "6300"))
    global_deadline = time.time() + total

    def solver(challenge: Challenge, started: StartResult,
               submit=None) -> list[str]:
        # 单题 780s（13 分钟）：上一轮 7 题各占满 900s 正好吃光 6300s 总预算，
        # 最后一道题拿到 0 秒被直接跳过。
        per = int(os.environ.get("BENCH_CHALLENGE_SECONDS", "780"))
        deadline = min(time.time() + per, global_deadline)
        if deadline <= time.time():
            emit("solve_skipped", unique_code=challenge.unique_code,
                 reason="全局时间预算已用尽")
            return []
        return solve_challenge(challenge, started, client, deadline=deadline,
                               max_steps=max_steps, shell_timeout=shell_timeout,
                               submit=submit)
    return solver
