"""真实靶标解题器：LLM 提议动作，代码执行并裁决 Flag。

设计沿用本项目既有的一条硬规则——**生成与判定分离**：
模型只负责在固定工具集里挑下一个动作、写出判断理由；动作由代码真正执行，
观测结果由代码记录，Flag 由代码用正则从真实响应里独立提取。
模型自报的 Flag 只作候选，必须能在观测里找到出处才提交，避免幻觉凑数。

工具集全部基于标准库，因为目标镜像 `python:3.11-slim` 里没有 nmap/curl/nc。

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

from .bench_client import Challenge, StartResult
from .events import emit

# Flag 提取分两档。原来只用一个宽正则 [A-Za-z0-9_]{2,32}\{...\}，
# 会把网页里的 JS/CSS 片段（如 .cls{a:b}）当成 Flag 提交，实测出现过
# 单题 5 次 answer_wrong。现在：强特征直接采信，弱特征必须带语义上下文。
STRONG_FLAG_PATTERNS = [
    re.compile(r"(?i)\b(?:flag|ctf|tsec|tsb|tflag|hack|pwn)\{[^}\n\r]{1,200}\}"),
    re.compile(r"(?i)\bflag[-_][A-Za-z0-9]{6,64}\b"),
]
WEAK_FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,32}\{[^}\n\r]{1,200}\}")

# 弱特征要成立的旁证：命中位置前后 200 字符内出现这些词才认。
FLAG_CONTEXT_HINTS = (
    "flag", "secret", "answer", "correct", "congrat", "success", "you win",
    "well done", "答案是", "恭喜", "正确", "提交", "这是你的", "拿到",
)

# 兼容旧调用方：对外仍暴露 FLAG_PATTERNS
FLAG_PATTERNS = STRONG_FLAG_PATTERNS + [WEAK_FLAG_PATTERN]

MAX_OBS_CHARS = 1800
MAX_STEPS_HARD_CAP = 60
# 单题最多提交多少条候选。提交次数是有成本的信号，不能无限往里灌。
MAX_FLAGS_PER_CHALLENGE = 15

SYSTEM_PROMPT = """你是一个在隔离沙箱里运行的授权 CTF 解题智能体。你的目标是从靶标拿到 Flag。

你只能通过下面的工具与靶标交互。每一轮必须输出**一个 JSON 对象**，不要输出任何解释性文字。

动作格式（二选一）：
{"thought": "为什么做这一步", "tool": "工具名", "args": {...}}
{"thought": "结论", "flags": ["flag 字符串", ...]}

工具清单：
1. http_request   args: {"method":"GET","path":"/","headers":{},"body":""}
   通用 HTTP 请求。path 可写相对路径（自动拼到靶标地址）或完整 URL。会保持 cookie。
2. http_get       args: {"path":"/"}
3. http_post      args: {"path":"/login","body":"a=1&b=2","content_type":"application/x-www-form-urlencoded"}
4. port_scan      args: {"ports":[80,443,8080]}  只扫靶标主机。
5. tcp_send       args: {"port":6379,"payload":"PING\\r\\n"}  原始 TCP，收发一次，用于非 HTTP 服务。
6. shell          args: {"command":"ls -la"}  在沙箱内执行 shell 命令（可访问靶标网络）。
7. decode         args: {"value":"...","kind":"base64|hex|url|rot13"}

硬性规则：
- 不要编造 Flag。只有在你确实看到过时才写进 flags，系统会回查观测，对不上的一律丢弃。
- 先侦察再攻击：先看清服务是什么、有哪些路径、什么参数，再构造利用。
- 每次只做一步，观察结果再决定下一步。重复同样的请求没有意义，要换思路。
- Flag 通常出现在响应体、报错信息、目录列表或某个文件里。找不到就扩大侦察面。
- 如果某个方向连续失败两次，换一个方向。
- 只有在已经拿到 Flag 时才输出 flags 动作。没拿到就继续输出工具动作；
  空 flags 会被系统追问一次，第二次才会真的结束本题，别拿它当省事的退出口。
- 全局时间预算有限（单题约 15 分钟），侦察要有节奏，别把预算全花在探测上。"""


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
    """单个靶标的解题上下文。"""

    base_url: str
    host: str
    ports: list[int] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    jar: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)


def parse_targets(container_addr: list[str]) -> tuple[str, str, list[int]]:
    """从 container_addr 里解析出 base_url、host、已给端口。"""
    base_url = ""
    host = ""
    ports: list[int] = []
    for addr in container_addr:
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
        if not base_url and parts.scheme in ("http", "https"):
            netloc = parts.netloc
            base_url = f"{parts.scheme}://{netloc}"
    if not base_url and host:
        port = ports[0] if ports else 80
        base_url = f"http://{host}:{port}"
    return base_url.rstrip("/"), host, ports


class Toolkit:
    """固定工具集。每个方法返回给模型看的文本观测。"""

    def __init__(self, context: SolveContext, shell_timeout: int = 30,
                 http_timeout: int = 15):
        self.context = context
        self.shell_timeout = shell_timeout
        self.http_timeout = http_timeout
        # 打靶流量必须直连。环境里若带 http_proxy/https_proxy（平台注入的
        # 出网代理），urllib 会把发往靶标的请求也塞进代理，结果是 502 而不是靶标响应。
        # 显式给空 ProxyHandler 关掉代理，只影响本工具集，不影响模型请求。
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(context.jar),
        )
        self._env_opener = None  # 懒加载；False 表示环境没配代理，不再尝试

    # -- 内部 ------------------------------------------------------

    def _absolute(self, path: str) -> str:
        path = str(path or "/").strip()
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.context.base_url + path

    @staticmethod
    def _clip(text: str, limit: int = MAX_OBS_CHARS) -> str:
        text = text if isinstance(text, str) else str(text)
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n...[截断，共 {len(text)} 字符]"

    # -- 工具 ------------------------------------------------------

    def http_request(self, method: str = "GET", path: str = "/",
                     headers: dict | None = None, body: str = "") -> str:
        url = self._absolute(path)
        data = body.encode("utf-8") if body else None
        verb = str(method or "GET").upper()
        hdrs = {str(k): str(v) for k, v in (headers or {}).items()}

        def send(opener) -> str:
            request = urllib.request.Request(url, data=data, method=verb, headers=hdrs)
            with opener.open(request, timeout=self.http_timeout) as response:
                text = response.read().decode("utf-8", errors="replace")
                head = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
                return self._clip(f"HTTP {response.status} {url}\n{head}\n\n{text}")

        try:
            return send(self._opener)
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            head = "\n".join(f"{k}: {v}" for k, v in exc.headers.items())
            return self._clip(f"HTTP {exc.code} {url}\n{head}\n\n{text}")
        except Exception as exc:  # 网络层失败也算观测，不中断循环
            # 直连不通时再试环境代理：某些沙箱只允许经代理访问靶标容器。
            alt = self._env_proxy_opener()
            if alt is not None:
                try:
                    return "[直连失败，已改走环境代理]\n" + send(alt)
                except Exception:
                    pass
            return f"请求失败 {url}: {type(exc).__name__}: {exc}"

    def _env_proxy_opener(self):
        """懒加载代理通道。环境里没配代理就返回 None，避免无谓重试。"""
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

    def port_scan(self, ports: list | None = None) -> str:
        targets = []
        for p in (ports or self.context.ports or [21, 22, 25, 80, 443, 3306,
                                                  5432, 6379, 8080, 8000, 8888, 9000]):
            try:
                targets.append(int(p))
            except (TypeError, ValueError):
                continue
        if not self.context.host:
            return "没有可用主机地址"
        open_ports, closed = [], []
        for port in targets[:64]:
            sock = socket.socket()
            sock.settimeout(1.5)
            try:
                sock.connect((self.context.host, port))
                open_ports.append(port)
            except OSError:
                closed.append(port)
            finally:
                sock.close()
        return f"主机 {self.context.host} 开放端口: {open_ports}\n未开放: {closed}"

    def tcp_send(self, port: int, payload: str = "", read_bytes: int = 4096) -> str:
        if not self.context.host:
            return "没有可用主机地址"
        try:
            port = int(port)
        except (TypeError, ValueError):
            return "port 必须是整数"
        data = payload.encode("utf-8", errors="replace") if payload else b""
        try:
            with socket.create_connection((self.context.host, port),
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

    def shell(self, command: str) -> str:
        command = str(command or "").strip()
        if not command:
            return "command 为空"
        # 同样去掉代理变量，保证 shell 里的 curl/python 也是直连靶标
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        try:
            completed = subprocess.run(
                ["bash", "-lc", command],
                capture_output=True, timeout=self.shell_timeout,
                cwd="/tmp", text=True, errors="replace", env=env,
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

    # -- 分发 ------------------------------------------------------

    ALLOWED = {
        "http_request": "http_request",
        "http_get": "http_get",
        "http_post": "http_post",
        "port_scan": "port_scan",
        "tcp_send": "tcp_send",
        "shell": "shell",
        "decode": "decode",
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


def _flag_context_hint(text: str, start: int, end: int,
                       window: int = 200) -> str | None:
    """命中位置前后 window 字符内是否有 flag 语义旁证，返回命中的提示词。"""
    around = text[max(0, start - window):min(len(text), end + window)].lower()
    for hint in FLAG_CONTEXT_HINTS:
        if hint in around:
            return hint
    return None


def extract_flags(text: str, strict: bool = False) -> list[str]:
    """从观测文本里提取候选 Flag。去重、保持首次出现顺序。

    两档判定：强特征（flag{...}/CTF{...} 之类）直接采信；弱特征（任意
    `xxx{...}`）必须带语义旁证，否则丢弃并推一条 flag_suspect_skipped，
    避免把网页里的 JS/CSS 片段当 Flag 提交。strict=True 只走强特征。
    """
    body = text if isinstance(text, str) else str(text or "")
    if not body:
        return []
    found: list[str] = []
    seen: set[str] = set()
    strong_spans: list[tuple[int, int]] = []

    for pattern in STRONG_FLAG_PATTERNS:
        for match in pattern.finditer(body):
            value = match.group(0).strip()
            key = value.lower()
            if len(value) < 6 or key in seen:
                continue
            seen.add(key)
            found.append(value)
            strong_spans.append((match.start(), match.end()))

    if strict:
        return found

    for match in WEAK_FLAG_PATTERN.finditer(body):
        value = match.group(0).strip()
        key = value.lower()
        if len(value) < 6 or key in seen:
            continue
        if any(start <= match.start() and match.end() <= end
               for start, end in strong_spans):
            continue
        hint = _flag_context_hint(body, match.start(), match.end())
        if hint is None:
            emit("flag_suspect_skipped", candidate=value[:120],
                 reason="弱特征且前后 200 字符内无 flag 语义旁证")
            continue
        seen.add(key)
        found.append(value)
        emit("flag_weak_accepted", candidate=value[:120], hint=hint)
    return found


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
    depth = 0
    start = -1
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


def _build_user_prompt(challenge: Challenge, context: SolveContext) -> str:
    lines = [
        "## 题目",
        f"编号: {challenge.unique_code}",
        f"难度: {challenge.difficulty or '未知'}  等级: {challenge.level}",
        f"分值: {challenge.total_score}  Flag 数量: {challenge.flag_count}",
        "",
        "## 题面",
        challenge.description.strip() or "（平台未给出题面描述，只能靠主动侦察）",
        "",
        "## 靶标地址",
    ]
    if context.base_url:
        lines.append(f"base_url = {context.base_url}")
    if context.host:
        lines.append(f"host = {context.host}")
    if context.ports:
        lines.append(f"已知端口 = {context.ports}")
    lines += ["", "从侦察开始。每次只输出一个 JSON 动作。"]
    return "\n".join(lines)


def _render_transcript(context: SolveContext, limit: int = 8,
                       clip: int = 1100) -> str:
    """只带最近若干步。每步都重发全量观测会让 token 随步数平方膨胀。"""
    if not context.observations:
        return "（还没有任何观测，先做第一次侦察）"
    recent = context.observations[-limit:]
    blocks = []
    for obs in recent:
        args = json.dumps(obs.args, ensure_ascii=False)[:180]
        output = obs.output
        if len(output) > clip:
            output = output[:clip] + f"...[截断，原长 {len(obs.output)}]"
        thought = f"\n(当时判断：{obs.thought[:120]})" if obs.thought else ""
        blocks.append(f"### 第 {obs.step} 步  {obs.tool}({args}){thought}\n{output}")
    return "\n\n".join(blocks)


def solve_challenge(challenge: Challenge, started: StartResult,
                    client, *, deadline: float | None = None,
                    max_steps: int | None = None,
                    shell_timeout: int = 30) -> list[str]:
    """跑单道题：侦察 → 利用 → 提 Flag。返回通过观测核验的 Flag 列表。"""
    base_url, host, ports = parse_targets(started.container_addr)
    if not base_url and not host:
        emit("solve_no_target", unique_code=challenge.unique_code,
             container_addr=started.container_addr,
             note="平台未返回可用靶标地址")
        return []

    context = SolveContext(base_url=base_url, host=host, ports=ports)
    toolkit = Toolkit(context, shell_timeout=shell_timeout)
    steps = max_steps or int(os.environ.get("BENCH_MAX_STEPS", "40"))
    steps = max(1, min(steps, MAX_STEPS_HARD_CAP))
    if deadline is None:
        budget = int(os.environ.get("BENCH_CHALLENGE_SECONDS", "780"))
        deadline = time.time() + budget

    emit("solve_begin", unique_code=challenge.unique_code,
         base_url=base_url, host=host, ports=ports,
         max_steps=steps, budget_seconds=int(deadline - time.time()))

    user_prompt = _build_user_prompt(challenge, context)
    verified: list[str] = []
    seen_flags: set[str] = set()
    give_ups = 0

    for step in range(1, steps + 1):
        if time.time() >= deadline:
            emit("solve_timeout", unique_code=challenge.unique_code, step=step)
            break
        # 每步独立构造单条消息：上下文只由「题面 + 最近几步观测」决定，
        # 不累积历史消息，避免 token 随步数平方增长撑爆窗口。
        remaining = max(0, int(deadline - time.time()))
        turn = [
            user_prompt,
            "",
            "## 已有观测",
            _render_transcript(context),
            "",
            f"## 进度\n第 {step}/{steps} 步，剩余约 {remaining} 秒。",
            "请输出下一步动作（单个 JSON 对象）。",
        ]
        started_at = time.time()
        try:
            reply = client.complete(SYSTEM_PROMPT,
                                    messages=[{"role": "user",
                                               "content": "\n".join(turn)}])
        except Exception as exc:
            emit("solve_llm_error", unique_code=challenge.unique_code,
                 step=step, detail=f"{type(exc).__name__}: {exc}"[:200])
            break
        text = reply.get("text") or ""

        action = _extract_json_object(text)
        if not action:
            emit("solve_bad_action", unique_code=challenge.unique_code,
                 step=step, raw=text[:200])
            context.observations.append(Observation(
                step, "(无效动作)", {}, f"模型输出不是合法 JSON：{text[:200]}",
                time.time() - started_at))
            continue

        thought = str(action.get("thought") or "")[:300]

        if "flags" in action and "tool" not in action:
            claimed = [str(f).strip() for f in (action.get("flags") or [])
                       if str(f).strip()]
            corpus = "\n".join(o.output for o in context.observations)
            gained = 0
            for flag in claimed:
                key = flag.lower()
                if key in seen_flags:
                    continue
                if flag in corpus:
                    seen_flags.add(key)
                    verified.append(flag)
                    gained += 1
                    emit("solve_flag_verified", unique_code=challenge.unique_code,
                         step=step, flag=flag, source="模型声明且观测可核验")
                else:
                    emit("solve_flag_rejected", unique_code=challenge.unique_code,
                         step=step, flag=flag[:120],
                         reason="观测里找不到出处，拒绝提交")
            # 模型宣布收工但一个都没核验上，不能就此停手——上一轮实测里
            # 模型常在三四步就交白卷，把剩下的十几分钟预算全扔了。
            give_ups += 1
            if gained or give_ups >= 2:
                emit("solve_final", unique_code=challenge.unique_code, step=step,
                     thought=thought, verified=len(verified))
                break
            context.observations.append(Observation(
                step, "(模型声称已收工)", {},
                "你声称的 Flag 在已有观测里都找不到出处，因此一条都没被采信。"
                "本题还没拿到 Flag，请继续侦察或换方向，仍然每次输出一个工具动作。"
                "若确实无法继续，再输出一次 {\"flags\": []} 即结束本题。",
                time.time() - started_at, thought))
            emit("solve_give_up_denied", unique_code=challenge.unique_code,
                 step=step, claimed=len(claimed))
            continue

        tool = str(action.get("tool") or "")
        args = action.get("args") or {}
        output = toolkit.run(tool, args)
        context.observations.append(
            Observation(step, tool, args if isinstance(args, dict) else {},
                        output, time.time() - started_at, thought))
        emit("solve_step", unique_code=challenge.unique_code, step=step,
             tool=tool, thought=thought,
             args=json.dumps(args, ensure_ascii=False)[:300],
             output=output[:500], elapsed=round(time.time() - started_at, 2))

        # 代码侧独立提取，不依赖模型是否注意到
        for flag in extract_flags(output):
            if len(verified) >= MAX_FLAGS_PER_CHALLENGE:
                emit("solve_flag_budget_full", unique_code=challenge.unique_code,
                     step=step, cap=MAX_FLAGS_PER_CHALLENGE)
                break
            key = flag.lower()
            if key in seen_flags:
                continue
            seen_flags.add(key)
            verified.append(flag)
            emit("solve_flag_found", unique_code=challenge.unique_code,
                 step=step, flag=flag, source="观测正则提取")
        if len(verified) >= max(1, challenge.flag_count or 1):
            break

    emit("solve_done", unique_code=challenge.unique_code,
         steps=len(context.observations), flags=len(verified))
    return verified


def make_llm_solver(*, max_steps: int | None = None,
                    total_seconds: int | None = None,
                    shell_timeout: int = 30) -> Callable[[Challenge, StartResult], list[str]]:
    """构造一个带全局时间预算的解题器，供 run_benchmark 注入。"""
    from .llm import MiniMaxClient, get_config

    client = MiniMaxClient(get_config())
    total = total_seconds or int(os.environ.get("BENCH_TOTAL_SECONDS", "6300"))
    global_deadline = time.time() + total

    def solver(challenge: Challenge, started: StartResult) -> list[str]:
        # 单题上限取 780s（13 分钟）而不是 900s：上一轮 7 道题各占满 900s，
        # 正好等于全局 6300s，最后一道题拿到 0 秒被直接跳过。
        per = int(os.environ.get("BENCH_CHALLENGE_SECONDS", "780"))
        deadline = min(time.time() + per, global_deadline)
        if deadline <= time.time():
            emit("solve_skipped", unique_code=challenge.unique_code,
                 reason="全局时间预算已用尽")
            return []
        return solve_challenge(challenge, started, client,
                               deadline=deadline, max_steps=max_steps,
                               shell_timeout=shell_timeout)
    return solver
