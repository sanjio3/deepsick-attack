"""探测器与候选动作：把「自由发挥」换成「从候选里挑」。

原来让 Flash 模型每步自己编一个 JSON 动作，等于让它在一个无限动作空间里搜索，
40 步内基本不可能收敛。这里做两件事：

1. 由代码根据事实板生成 4-8 条候选动作（intent），模型只负责挑一条、或明确
   要求走自定义动作。决策面从「任意动作」缩到「N 选 1」，这是 Flash 级模型
   能力范围内能做的判断。
2. 每条动作执行后由 detector 判结果，不看模型自述——这是 garak 的用法：
   攻击生成与成功判定解耦，判定只吃真实字节。
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 蜜罐/主动防御的典型话术。命中不直接判死，但会把该服务标成 risky。
TRIPWIRE_MARKERS = (
    "detected", "blocked", "banned", "intrusion", "alarm", "honeypot",
    "unauthorized access", "logged", "reported", "you have been", "trap",
    "检测到", "已记录", "已上报", "封禁", "拦截", "蜜罐", "告警", "入侵",
)

# 「太配合」的响应：一次请求就给 root/shell/全部文件，通常不是真漏洞。
TOO_EASY_MARKERS = (
    "uid=0(root)", "root:x:0:0", "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
)

# 已试过就别再试的路径黑名单（对 honeypot 判断有用，对拿 flag 无用）
NOISE_PATHS = ("/favicon.ico",)


@dataclass
class Candidate:
    id: str
    label: str
    tool: str
    args: dict
    why: str
    risk: str = "low"

    def line(self) -> str:
        risk = "" if self.risk == "low" else f" [risk={self.risk}]"
        return f"- {self.id}: {self.label}{risk} — {self.why}"


@dataclass
class Probe:
    """一次动作的结果判定。"""
    flags: list[str] = field(default_factory=list)
    tripwire: str | None = None
    too_easy: str | None = None
    status: int | None = None


def detect(text: str) -> Probe:
    """只吃真实响应文本。模型说什么都不影响判定。"""
    from .flags import extract_flags

    body = text or ""
    probe = Probe(flags=extract_flags(body))
    low = body.lower()
    for marker in TRIPWIRE_MARKERS:
        if marker in low:
            probe.tripwire = marker
            break
    for marker in TOO_EASY_MARKERS:
        if marker in body:
            probe.too_easy = marker
            break
    head = body.split("\n", 1)[0]
    if head.startswith("HTTP "):
        parts = head.split()
        if len(parts) >= 2 and parts[1].isdigit():
            probe.status = int(parts[1])
    return probe


def _http_candidates(host: str, port: int, scheme: str, risky: bool) -> list[Candidate]:
    base = f"{scheme}://{host}:{port}"
    risk = "high" if risky else "low"
    raw = [
        ("home", "GET 首页，看框架与入口", "/", "任何 Web 题的第一步"),
        ("robots", "读 robots.txt", "/robots.txt", "常泄露隐藏目录"),
        ("git", "查 .git/HEAD 是否暴露", "/.git/HEAD", "源码泄露高频点"),
        ("admin", "查管理入口", "/admin/", "后台常无鉴权或弱口令"),
        ("login", "查登录页", "/login", "口令注入/绕过的入口"),
        ("api", "查 API 文档或健康检查", "/api/health", "内部接口常漏鉴权"),
        ("status", "查服务器状态页", "/server-status", "可能泄露路径与请求"),
        ("missing", "请求一个必然不存在的路径", "/__no_such_path_9f3a__",
         "蜜罐常对任意路径返回 200，这是最便宜的识别手段"),
        ("methods", "OPTIONS 看允许的方法", "/", "PUT/DELETE 常被遗忘"),
    ]
    out: list[Candidate] = []
    for key, label, path, why in raw:
        tool = "http_request" if key == "methods" else "http_get"
        args = ({"method": "OPTIONS", "path": path} if key == "methods"
                else {"path": path})
        out.append(Candidate(f"http:{port}:{key}", f"[{port}] {label}",
                             tool, args, why, risk))
    out[0].args["path"] = base + "/"
    return out


def _ssh_candidates(host: str, port: int, board, risky: bool) -> list[Candidate]:
    out = [Candidate(f"ssh:{port}:audit", f"[{port}] 读 SSH banner 与算法",
                     "ssh_audit", {"port": port},
                     "先确认版本与允许的认证方式，再决定要不要试口令",
                     "high" if risky else "low")]
    cred_keys = [f.detail for f in board.of("credential")]
    if risky:
        # 已被标成可能触发告警的服务，不做任何认证尝试
        return out
    out.append(Candidate(
        f"ssh:{port}:auth", f"[{port}] 用少量已知口令试登录",
        "ssh_login", {"port": port},
        "只试 4 组常见口令，不做字典爆破——爆破最容易触发主动防御"))
    if cred_keys:
        out.append(Candidate(
            f"ssh:{port}:reuse", f"[{port}] 用已发现凭据复用登录",
            "ssh_login", {"port": port, "creds": cred_keys[:6]},
            "横向复用已泄露凭据，比猜更安全"))
    return out


def _service_candidates(host: str, fact_kind: str, port: int) -> list[Candidate]:
    table = {
        "redis": ("redis", "tcp_send", {"port": port, "payload": "PING\r\n"},
                  "未授权 Redis 直接读写，常见 flag 位置是 CONFIG GET dir"),
        "ftp": ("ftp", "tcp_send", {"port": port, "payload": "USER anonymous\r\n"},
                "匿名 FTP 可能直接给文件"),
        "mysql": ("mysql", "tcp_send", {"port": port, "payload": ""},
                  "MySQL 握手包能读到版本，弱口令可续接"),
        "vnc": ("vnc", "tcp_send", {"port": port, "payload": ""},
                "VNC 无认证时可直接截图（这里先读握手）"),
    }
    key, tool, args, why = table.get(fact_kind, ("", "", {}, ""))
    if not key:
        return []
    return [Candidate(f"{key}:{port}:probe", f"[{port}] {key} 探测",
                      tool, args, why)]


def propose(board, max_items: int = 8) -> list[Candidate]:
    """按事实板生成候选动作。已试过的、命中 risky 服务的排后面或剔除。"""
    host = board.host
    risky_keys = board.risky()
    pool: list[Candidate] = []

    services = board.services()
    if not services:
        pool.append(Candidate("meta:scan", "重新全端口扫描并抓 banner",
                              "rescan", {}, "还没有任何服务事实，先把面摸清"))
        pool.append(Candidate("meta:mdns", "用 mDNS 问本机公布了哪些服务",
                              "mdns", {}, "动态防御类靶标靠 mDNS 暴露真实端口"))
        return pool[:max_items]

    for fact in services:
        port = fact.key.rsplit(":", 1)[-1]
        try:
            port_no = int(port)
        except ValueError:
            continue
        risky = fact.key in risky_keys
        proto = fact.detail.split()[1] if len(fact.detail.split()) > 1 else ""
        if proto in ("http", "https"):
            pool.extend(_http_candidates(host, port_no, proto, risky))
        elif proto == "ssh":
            pool.extend(_ssh_candidates(host, port_no, board, risky))
        else:
            pool.extend(_service_candidates(host, proto, port_no))

    pool.append(Candidate("meta:mdns", "用 mDNS 问本机公布了哪些服务",
                          "mdns", {}, "动态靶标可能只在 mDNS 里公布真实端点"))
    pool.append(Candidate("meta:rescan", "重扫端口（服务可能已轮换）",
                          "rescan", {}, "移动靶会换端口"))
    pool.append(Candidate("meta:custom", "自己写一个动作（工具集见系统提示）",
                          "custom", {}, "候选都不合适时走自定义"))

    fresh, seen = [], set()
    for item in pool:
        if item.id in seen or item.id in board.tried:
            continue
        seen.add(item.id)
        fresh.append(item)
    # 命中 risky 服务的候选降到队尾，但保留——万一只有这一条路
    fresh.sort(key=lambda c: (c.risk == "high", 0))
    return fresh[:max_items]
