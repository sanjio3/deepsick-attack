"""持久会话：把「一次性请求」升级成「能交互的 shell」。

这是读完 CAI 源码后最直接的结论。CAI 的 CTF agent 系统提示里，工具只有**一个**
`generic_linux_command`，真正的能力来自它的会话参数：

    generic_linux_command("ssh user@host", interactive=True)   # 起会话
    generic_linux_command("id", session_id="<id>")             # 往会话里发
    generic_linux_command("session output <id>")                # 读回来

也就是说，能解题的 agent 不缺「机制」，缺的是**一个能维持状态的 shell**。
之前我们给模型的是 http_get / http_post / tcp_send 这些一次性原语，等于让它拿
螺丝刀开保险柜：反弹 shell、交互式 ssh、nc 传文件、python 反向连接，一个都做不了。

支持两种后端：
- proc：本地进程会话（bash / python -i / nc / socat），Linux 上用 pty，保证 ssh、
  nc 这类程序不因为 stdout 缓冲而卡住；Windows 上退化管道，只用于本地测试。
- ssh：paramiko 的 invoke_shell 通道，给只有 :22 的题用（本机没有 ssh 客户端，
  busybox 也没有，只能走 paramiko）。

输出统一做 ANSI 清理并按字节块累积，读取是按时间窗口取增量，不阻塞主循环。
"""
from __future__ import annotations

import collections
import os
import re
import subprocess
import threading
import time

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")
MAX_BUFFER_BYTES = 400_000


def _clean(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    text = _ANSI.sub("", text)
    return text.replace("\x00", "")


class Session:
    """一个持久会话。proc 与 ssh 通道共用这套读写接口。"""

    def __init__(self, sid: int, argv: list[str], use_pty: bool = False):
        self.sid = sid
        self.argv = argv
        self.use_pty = use_pty
        self.created = time.time()
        self._buffer: collections.deque[str] = collections.deque()
        self._pending = 0
        self._lock = threading.Lock()
        self._closed = False
        self._channel = None      # paramiko channel
        self._proc = None
        self._master_fd = None
        self._thread = None

    # -- 启动 ------------------------------------------------------

    def start_proc(self, env: dict | None = None) -> None:
        argv = self.argv
        if self.use_pty:
            import fcntl
            import pty
            import struct
            import termios
            master, slave = pty.openpty()
            # 窗口尺寸给大一点，避免某些程序按 80x24 截断输出
            fcntl.ioctl(slave, termios.TIOCSWINSZ,
                        struct.pack("HHHH", 200, 400, 0, 0))
            self._master_fd = master
            self._proc = subprocess.Popen(
                argv, stdin=slave, stdout=slave, stderr=slave,
                preexec_fn=os.setsid, env=env or os.environ.copy(),
                close_fds=True)
            os.close(slave)
            self._thread = threading.Thread(target=self._pump_fd, daemon=True)
        else:
            self._proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=0,
                env=env or os.environ.copy())
            self._thread = threading.Thread(target=self._pump_pipe, daemon=True)
        self._thread.start()

    def attach_channel(self, channel) -> None:
        self._channel = channel
        self._thread = threading.Thread(target=self._pump_channel, daemon=True)
        self._thread.start()

    # -- 读线程 ----------------------------------------------------

    def _push(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._lock:
            self._buffer.append(_clean(chunk))
            self._pending += len(chunk)
            total = sum(len(x) for x in self._buffer)
        while total > MAX_BUFFER_BYTES and len(self._buffer) > 1:
            with self._lock:
                if not self._buffer:
                    break
                total -= len(self._buffer.popleft())

    def _pump_fd(self) -> None:
        while not self._closed:
            try:
                chunk = os.read(self._master_fd, 8192)
            except OSError:
                break
            if not chunk:
                break
            self._push(chunk)

    def _pump_pipe(self) -> None:
        stream = self._proc.stdout if self._proc else None
        if stream is None:
            return
        fd = stream.fileno()
        while not self._closed:
            # 必须用 os.read：带缓冲的 .read(n) 会一直等到攒够 n 字节，
            # 交互式会话就永远读不到「现在已有的输出」。
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            self._push(chunk)

    def _pump_channel(self) -> None:
        while not self._closed and self._channel is not None:
            try:
                if self._channel.recv_ready():
                    self._push(self._channel.recv(8192))
                elif self._channel.closed or self._channel.exit_status_ready():
                    break
                else:
                    time.sleep(0.05)
            except Exception:  # noqa: BLE001 - 通道断开就是断开
                break

    # -- 读写 ------------------------------------------------------

    def write(self, text: str) -> None:
        data = text.encode("utf-8")
        if self._channel is not None:
            self._channel.send(data)
            return
        if self._master_fd is not None:
            os.write(self._master_fd, data)
            return
        if self._proc and self._proc.stdin:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()

    def read(self, wait: float = 2.0, settle: float = 0.25) -> str:
        """按时间窗口取增量。先等 wait 秒，之后静默 settle 秒即可返回。"""
        deadline = time.time() + wait
        last_size = -1
        while time.time() < deadline:
            with self._lock:
                size = self._pending
            if size and size == last_size:
                break
            last_size = size
            time.sleep(0.05)
        with self._lock:
            chunks = list(self._buffer)
            self._buffer.clear()
            self._pending = 0
        return "".join(chunks)

    def alive(self) -> bool:
        if self._channel is not None:
            return not self._channel.closed
        if self._proc is None:
            return False
        return self._proc.poll() is None

    def kill(self) -> None:
        self._closed = True
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:  # noqa: BLE001
                pass
        if self._proc is not None and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                try:
                    self._proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        if self._proc is not None:
            for stream in (self._proc.stdin, self._proc.stdout):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:  # noqa: BLE001
                    pass


class SessionManager:
    def __init__(self, limit: int = 4):
        self._sessions: dict[int, Session] = {}
        self._next = 1
        self.limit = limit

    def start(self, argv: list[str], use_pty: bool = False,
              env: dict | None = None) -> Session:
        if len(self._sessions) >= self.limit:
            oldest = min(self._sessions.values(), key=lambda s: s.created)
            self.kill(oldest.sid)
        session = Session(self._next, argv, use_pty)
        self._next += 1
        session.start_proc(env)
        self._sessions[session.sid] = session
        return session

    def attach(self, channel, label: str = "ssh") -> Session:
        session = Session(self._next, [label], False)
        self._next += 1
        session.attach_channel(channel)
        self._sessions[session.sid] = session
        return session

    def get(self, sid: int) -> Session | None:
        return self._sessions.get(int(sid))

    def list(self) -> list[dict]:
        return [{"id": s.sid, "cmd": " ".join(s.argv)[:80],
                 "alive": s.alive(), "age": round(time.time() - s.created, 1)}
                for s in self._sessions.values()]

    def kill(self, sid: int) -> bool:
        session = self._sessions.pop(int(sid), None)
        if session is None:
            return False
        session.kill()
        return True

    def close_all(self) -> None:
        for sid in list(self._sessions):
            self.kill(sid)


def pty_available() -> bool:
    if os.name != "posix":
        return False
    try:
        import fcntl  # noqa: F401
        import pty  # noqa: F401
        return True
    except ImportError:
        return False
