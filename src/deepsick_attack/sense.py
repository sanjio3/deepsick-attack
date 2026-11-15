"""感知层：只相信真实字节，不相信平台给的地址。

平台返回的 container_addr 只是线索——同一个宿主机 IP 上映射了多道题的不同端口，
给了 `:22` 不等于这题只有 SSH，也不等于它就是目标的入口。所以这里不看提示，
自己扫、自己抓 banner、自己判协议。

四件事：
1. TCP connect 扫（并发，不依赖 nmap），常用端口 + 提示端口 + 提示端口邻域
2. banner 抓取并按原始字节判协议（SSH/HTTP/TLS/FTP/SMTP/POP3/IMAP/MySQL/Redis/VNC）
3. UDP 探测，含 mDNS 服务公布（移动靶那类题靠 mDNS 暴露真实端口）
4. DNS 查询（含 TXT），flag 常常藏在 DNS 记录里而不是 HTTP body

第三方库只在 DNS 分支需要，缺失时降级返回说明，不抛异常打断主流程。
"""
from __future__ import annotations

import base64
import concurrent.futures
import re
import socket
import ssl
import struct
import urllib.error
import urllib.request
import time

# 常用端口。不追 nmap top1000 的全量，200 个覆盖 CTF 与常见服务足够，
# 单轮扫描 3-6 秒就能出结果，比全量 65535 的 3 分钟划算得多。
TOP_PORTS = [
    21, 22, 23, 25, 53, 69, 79, 80, 81, 82, 83, 84, 85, 88, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 179, 389, 443, 445, 464, 465, 512, 513, 514,
    515, 548, 554, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1025,
    1080, 1099, 1112, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083,
    2181, 2222, 2375, 2376, 2404, 3000, 3128, 3260, 3306, 3311, 3389, 3690,
    4000, 4369, 4444, 4505, 4506, 5000, 5037, 5060, 5222, 5269, 5353, 5432,
    5433, 5555, 5601, 5672, 5683, 5900, 5901, 5938, 5985, 5986, 6000, 6379,
    6443, 7001, 7002, 7077, 8000, 8001, 8008, 8009, 8010, 8032, 8042, 8069,
    8080, 8081, 8082, 8083, 8088, 8090, 8123, 8161, 8180, 8200, 8300, 8400,
    8443, 8444, 8500, 8529, 8880, 8888, 8889, 9000, 9001, 9042, 9060, 9090,
    9091, 9092, 9160, 9200, 9300, 9418, 9443, 9600, 9999, 10000, 10250,
    10255, 11211, 15672, 16379, 18080, 20000, 25565, 27017, 27018, 28017,
    50000, 50070, 54321, 55555, 61616,
]

HTTP_PORTS = {80, 81, 82, 83, 84, 85, 3000, 5000, 7001, 8000, 8001, 8008,
              8009, 8010, 8069, 8080, 8081, 8082, 8083, 8088, 8090, 8123,
              8180, 8200, 8300, 8400, 8500, 8888, 8889, 9000, 9001, 9090,
              9091, 9200, 10000, 15672, 18080, 50000, 50070}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 8444, 9443, 2376, 6443, 10250}

BANNER_SIGNATURES = (
    (b"SSH-", "ssh"),
    (b"HTTP/", "http"),
    (b"RFB ", "vnc"),
    (b"220 ", "ftp"),
    (b"+OK", "pop3"),
    (b"* OK", "imap"),
    (b"AMQP", "amqp"),
    (b"-ERR", "redis"),
    (b"REDIS", "redis"),
    (b"MongoDB", "mongodb"),
)


def expand_ports(hint_ports: list[int] | None, extra_span: int = 10,
                 deep: bool = False) -> list[int]:
    """把提示端口展开成扫描列表。

    关键决策：**平台给的地址是线索，同一宿主机 IP 上挂着多道题的不同端口**。
    所以默认只扫提示端口及其邻域，不去扫全端口——扫全端口会命中别的题的服务，
    把 agent 引去攻击错误容器。深度模式（找不到服务时升级）才扫全量表。
    """
    hints: set[int] = set()
    for raw in hint_ports or []:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 < port < 65536:
            hints.add(port)
    if not hints or deep:
        ports = set(TOP_PORTS) | hints
        for port in hints:
            for delta in range(1, extra_span + 1):
                ports.add(port + delta)
                if port - delta > 0:
                    ports.add(port - delta)
        return sorted(ports)
    ports = set(hints)
    for port in hints:
        for delta in range(1, extra_span + 1):
            if port + delta < 65536:
                ports.add(port + delta)
            if port - delta > 0:
                ports.add(port - delta)
    return sorted(ports)


def scan(host: str, ports: list[int], workers: int = 200,
         timeout: float = 0.6) -> list[int]:
    """并发 connect 扫描，返回开放端口。"""
    if not host:
        return []
    open_ports: list[int] = []

    def probe(port: int) -> int | None:
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return port
        except OSError:
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(probe, ports):
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)


def _read_passive(sock: socket.socket, limit: int = 512) -> bytes:
    """先等对端主动吐 banner（SSH/FTP/SMTP/MySQL 都是这样）。"""
    sock.settimeout(1.2)
    chunks: list[bytes] = []
    total = 0
    try:
        while total < limit:
            chunk = sock.recv(512)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\n" in chunk:
                break
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def _classify(raw: bytes, port: int, tls: bool) -> str:
    if tls:
        return "https"
    head = raw[:64]
    for signature, name in BANNER_SIGNATURES:
        if head.startswith(signature):
            return name
    if b"HTTP/" in head:
        return "http"
    # MySQL 握手包：3 字节长度 + 序号 0 + 协议版本 10
    if len(raw) >= 5 and raw[4] == 10 and raw[3] == 0:
        return "mysql"
    if port in HTTP_PORTS and raw:
        return "http"
    if port in TLS_PORTS:
        return "https"
    return "unknown"


def fingerprint(host: str, port: int, timeout: float = 2.5) -> dict:
    """抓 banner 并判协议。依次尝试：被动 banner → 明文 HTTP → TLS。"""
    result = {"host": host, "port": port, "proto": "unknown",
              "banner": "", "tls": False, "http_status": None}
    if not host:
        return result

    raw = b""
    tls = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            raw = _read_passive(sock)
            if raw:
                proto = _classify(raw, port, False)
                if proto == "ssh":
                    result.update(proto="ssh", banner=_text(raw, 200))
                    return result
                if proto in ("ftp", "smtp", "pop3", "imap", "mysql", "vnc",
                             "redis", "amqp", "mongodb"):
                    result.update(proto=proto, banner=_text(raw, 200))
                    return result
                if proto == "http":
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: " +
                                 host.encode() + b"\r\n\r\n")
                    more = _read_passive(sock, 4096)
                    raw = raw + more
                    result.update(proto="http", banner=_text(raw, 400),
                                  http_status=_status(raw))
                    return result
            # 没有任何被动 banner，主动发 HTTP
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " +
                         host.encode() + b"\r\n\r\n")
            more = _read_passive(sock, 4096)
            if more.startswith(b"HTTP/"):
                result.update(proto="http", banner=_text(more, 400),
                              http_status=_status(more))
                return result
            if more:
                result.update(banner=_text(more, 200))
                return result
    except (OSError, ssl.SSLError):
        pass

    # 兜底试 TLS
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(b"GET / HTTP/1.0\r\nHost: " +
                                 host.encode() + b"\r\n\r\n")
                data = tls_sock.recv(4096)
                result.update(proto="https", tls=True, banner=_text(data, 400),
                              http_status=_status(data))
                return result
    except (OSError, ssl.SSLError):
        pass
    return result


def _status(raw: bytes) -> int | None:
    head = raw.split(b"\r\n", 1)[0]
    parts = head.split()
    if len(parts) >= 2 and parts[0].startswith(b"HTTP/") and parts[1].isdigit():
        return int(parts[1])
    return None


def _text(raw: bytes, limit: int) -> str:
    return raw[:limit].decode("utf-8", errors="replace").strip()


def udp_probe(host: str, port: int, payload: bytes = b"\x00",
              timeout: float = 1.5) -> bytes:
    if not host:
        return b""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            data, _ = sock.recvfrom(4096)
            return data
    except OSError:
        return b""


def _encode_dns_query(name: str, qtype: int = 255) -> bytes:
    """极简 DNS 查询编码（ANY 记录），避免依赖 dnspython 才能发包。"""
    tid = struct.pack(">H", 0x1234)
    flags = struct.pack(">H", 0x0100)
    header = tid + flags + struct.pack(">HHHH", 1, 0, 0, 0)
    qname = b""
    for label in name.split("."):
        if label:
            qname += bytes([len(label)]) + label.encode("ascii", "ignore")
    qname += b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def mdns_services(timeout: float = 2.0) -> list[str]:
    """通过 mDNS 问 `_services._dns-sd._udp.local`，列出本机公布的服务类型。

    移动靶这类题靠 mDNS 动态公布真实服务，硬扫端口是扫不到的。
    """
    payload = _encode_dns_query("_services._dns-sd._udp.local", 12)
    names: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                           socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.sendto(payload, ("224.0.0.251", 5353))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    break
                for name in _parse_dns_names(data):
                    if name not in names:
                        names.append(name)
    except OSError:
        pass
    return names


def _parse_dns_names(data: bytes) -> list[str]:
    """从 DNS 报文里捞出可读的域名（不做完整解析，只做服务发现用）。"""
    names: list[str] = []
    idx = 12
    while idx < len(data):
        length = data[idx]
        if length == 0:
            idx += 1
            continue
        if length & 0xC0 == 0xC0:
            idx += 2
            continue
        label = data[idx + 1: idx + 1 + length]
        if not label or any(b < 0x20 or b > 0x7E for b in label):
            idx += 1 + length
            continue
        parts = [label.decode("ascii", "ignore")]
        cursor = idx + 1 + length
        while cursor < len(data):
            sub_len = data[cursor]
            if sub_len == 0 or sub_len & 0xC0:
                break
            sub = data[cursor + 1: cursor + 1 + sub_len]
            if not sub or any(b < 0x20 or b > 0x7E for b in sub):
                break
            parts.append(sub.decode("ascii", "ignore"))
            cursor += 1 + sub_len
        candidate = ".".join(parts)
        if len(parts) >= 2 and candidate not in names:
            names.append(candidate)
        idx += 1 + length
    return names[:24]


def dns_query(name: str, qtype: str = "TXT", server: str | None = None) -> str:
    """用 dnspython 查一条记录；没装就退回手工查询的原始十六进制。"""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        raw = udp_probe(server or "8.8.8.8", 53, _encode_dns_query(name))
        return f"dnspython 不可用，原始响应 {len(raw)} 字节：{raw[:200]!r}"
    resolver = dns.resolver.Resolver(configure=server is None)
    if server:
        resolver.nameservers = [server]
    resolver.timeout = 3
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(name, qtype)
        return "\n".join(str(item) for item in answers)
    except Exception as exc:  # noqa: BLE001 - 查询失败也是观测
        return f"查询 {name} {qtype} 失败：{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------- 路由发现

_ROUTE_RE = re.compile(r"""["'`](/(?:[A-Za-z0-9_.\-]+/?){1,6})["'`]""")
_ATTR_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']{1,200})["']""", re.I)
_JS_URL_RE = re.compile(r"""(?:url|fetch|open|ajax|post|get)\s*[:(]\s*["'`]([^"'`]{1,200})["'`]""", re.I)


def extract_routes(html: str, scripts: str = "", limit: int = 40) -> list[str]:
    """从首页与前端 JS 里抽路由。

    这是纯确定性工作，不该花模型步数。实测 a-04「企业内容管理系统」里模型用
    六步反复下载同一个 app.js，就是为了从里面捞出 `/api/upload.php` 和 key 的
    用法；这一步交给代码，模型直接从清单里挑。
    """
    found: list[str] = []
    seen: set[str] = set()

    def push(path: str) -> None:
        path = (path or "").strip()
        if not path or len(path) > 120:
            return
        if path.startswith("//") or path.startswith("http"):
            return
        if not path.startswith("/"):
            return
        if path.lower().endswith((".css", ".png", ".jpg", ".jpeg", ".gif",
                                  ".svg", ".ico", ".woff", ".woff2", ".ttf")):
            return
        if path in seen:
            return
        seen.add(path)
        found.append(path)

    for m in _ATTR_RE.finditer(html or ""):
        push(m.group(1))
    for m in _ROUTE_RE.finditer(html or ""):
        push(m.group(1))
    for text in (scripts or "",):
        for m in _JS_URL_RE.finditer(text):
            push(m.group(1))
        for m in _ROUTE_RE.finditer(text):
            push(m.group(1))
    return found[:limit]


def fetch_assets(base_url: str, html: str, timeout: float = 5.0,
                 max_scripts: int = 4, limit_bytes: int = 400_000) -> str:
    """抓首页引用到的 JS，拼成一段文本。抓不到就返回空串。"""
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        return ""
    chunks: list[str] = []
    for m in re.finditer(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", html or "", re.I):
        src = m.group(1).strip()
        if src.startswith("//"):
            src = "http:" + src
        url = src if src.startswith("http") else base_url + "/" + src.lstrip("/")
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                raw = response.read(limit_bytes)
            chunks.append(raw.decode("utf-8", "replace"))
        except Exception:
            continue
        if len(chunks) >= max_scripts:
            break
    return "\n".join(chunks)


_SECRET_RE = re.compile(
    r"""(?i)["']?([A-Za-z0-9_\-]{0,20}(?:api[_-]?key|apikey|secret|token|passwd|password)[A-Za-z0-9_\-]{0,10})["']?\]?\s*[:=,]\s*["']([^"'\s]{4,80})["']""")


def extract_secrets(text: str, limit: int = 8) -> list[str]:
    """从前端 JS 里捞硬编码凭据。

    真实靶标里凭据至少有两种写法，两种都要认：
        headers['X-API-Key'] = 'cms_int_svc_xxx'
        formData.append('api_key', 'cms_int_svc_xxx')
    只认 `key: value` / `key = value` 会两个都漏（a-04 实测返回 0 条）。
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _SECRET_RE.finditer(text or ""):
        name, value = m.group(1), m.group(2)
        if value.lower() in ("null", "undefined", "true", "false"):
            continue
        key = f"{name}={value}"
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out[:limit]


# base64 候选：前端代码里很常见（注释掉的密码、硬编码 token、混淆的配置）
_B64_RE = re.compile(r"""["'`]([A-Za-z0-9+/]{8,64}={0,2})["'`]""")
# 解码后像凭据的特征词
_CRED_WORDS = ("password", "passwd", "admin", "root", "secret", "token",
               "123456", "username", "pwd", "credential", "login")


def extract_encoded_secrets(text: str, limit: int = 8) -> list[str]:
    """从前端代码里找 base64 编码的凭据并解出来。

    a-17 的 hint 是「前端代码里是不是留下了什么蛛丝马迹」——实测模型为此把
    前端 JS 读了五遍，每遍只 grep 关键词，始终没把藏在 base64 里的凭据用上。
    这类活该由代码做：成本 0 步，而且不会漏。
    """
    out: list[str] = []
    for match in _B64_RE.finditer(text or ""):
        blob = match.group(1)
        if len(blob) % 4:
            blob += "=" * (4 - len(blob) % 4)
        try:
            decoded = base64.b64decode(blob, validate=False).decode("utf-8", "replace")
        except Exception:
            continue
        if len(decoded) < 4 or not decoded.isprintable():
            continue
        if not any(word in decoded.lower() for word in _CRED_WORDS):
            continue
        # 解出来常常是一段 JSON 片段（['admin','password123']），拼成 user:pass
        parts = [p.strip(" '\"[]") for p in re.split(r"[,\s]+", decoded)
                 if p.strip(" '\"[]")]
        item = f"{parts[0]}:{parts[1]}" if len(parts) >= 2 else decoded
        if item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def combine_routes(routes: list[str], limit: int = 24) -> list[str]:
    """把「基址 + 相对路由」拼成真实路径。

    前端常见 `apiBase: '/api'` 然后 `fetch(this.apiBase + '/upload.php')`，
    单纯抽字符串会得到两个互不相干的 `/api` 和 `/upload.php`，而真实入口是
    `/api/upload.php`——a-04 的整条利用链就在这个拼接上。
    """
    bases = [r for r in routes if r.rstrip("/").count("/") <= 2
             and r.rstrip("/").lower().endswith(("api", "api/v1", "v1", "v2", "admin"))]
    out: list[str] = []
    seen: set[str] = set()
    for route in routes:
        if route not in seen:
            seen.add(route)
            out.append(route)
    for base in bases:
        clean = base.rstrip("/")
        for route in routes:
            if route == base or route.startswith(clean + "/"):
                continue
            joined = clean + "/" + route.lstrip("/")
            if joined not in seen:
                seen.add(joined)
                out.append(joined)
    return out[:limit]


# 常见敏感/备份/调试路径。实跑轨迹里模型为这些路径花了二三十步，一步一个 curl；
# 这些探测本身不带任何智力成分，应该由代码一次打完，把步数留给真正需要判断的地方。
PROBE_PATHS = (
    "/robots.txt", "/sitemap.xml", "/.DS_Store", "/package.json", "/composer.json",
    "/.git/HEAD", "/.git/config", "/.env", "/.env.bak",
    "/backup/", "/backup.zip", "/backup.sql", "/backup.tar.gz", "/db.sql",
    "/dump.sql", "/data.sql", "/www.zip", "/www.tar.gz", "/source.zip", "/src.zip",
    "/index.php.bak", "/index.php~", "/config.php.bak", "/config.php~",
    "/admin", "/admin/", "/login", "/login.php", "/logout",
    "/api/", "/api/docs", "/swagger-ui.html", "/swagger/index.html",
    "/openapi.json", "/v2/api-docs", "/actuator", "/actuator/env",
    "/console", "/debug", "/server-status", "/uploads/", "/files/",
    "/flag", "/flag.txt", "/phpinfo.php", "/info.php",
)

# 这些状态码说明「路径存在」（只是没给看），比 404 更值得记。
_ALIVE_STATUS = (200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 503)


def bulk_probe(base_url: str, paths: tuple[str, ...] | list[str] | None = None,
               timeout: float = 4.0, workers: int = 12,
               limit_bytes: int = 60_000) -> list[dict]:
    """一次性把一批敏感路径打完，只回「有响应」的那些。

    设计目标是省步数：一次动作拿到的信息量，等价于模型一步一个 curl 打几十步。
    `status=404` 的不算命中；401/403 算命中（路径存在，只是要绕过）。
    """
    base = (base_url or "").rstrip("/")
    if not base.startswith("http"):
        return []
    targets = list(paths or PROBE_PATHS)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def one(path: str) -> dict | None:
        try:
            with opener.open(base + path, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                raw = response.read(limit_bytes)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read(limit_bytes) or b""
            except Exception:
                raw = b""
        except Exception:
            return None
        if status not in _ALIVE_STATUS:
            return None
        return {"path": path, "status": status, "length": len(raw),
                "snippet": re.sub(r"\s+", " ", _text(raw, 240))[:120]}

    hits: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for result in pool.map(one, targets):
            if result:
                hits.append(result)
    hits.sort(key=lambda item: item["path"])
    return hits


def read_url(url: str, timeout: float = 6.0, limit_bytes: int = 200_000) -> str:
    """取一个地址的正文。探到备份/配置文件时用它把内容捞出来。"""
    if not url.startswith("http"):
        return ""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            return _text(response.read(limit_bytes), limit_bytes)
    except Exception:
        return ""
