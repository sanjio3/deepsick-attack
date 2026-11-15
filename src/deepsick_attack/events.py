"""结构化事件输出。

所有运行状态都通过 emit 往外推，不在后台静默执行。默认输出到 stdout，
前端可以调用 set_sink 接管事件流，测试也可以注入收集器避免污染输出。

本地 Agent 模式下平台侧不记录我们的模型会话（模型调用不经平台网关时，
/llm/sessions 里没有数据），复盘只能靠自己落盘，所以另有一条写文件的出口：
set_log_file() 之后每条事件都会同时追加成一行 JSON。
"""
from __future__ import annotations

import json
import os
import sys
import threading
from typing import Any, Callable, TextIO

Sink = Callable[[dict[str, Any]], None]
_sink: Sink | None = None
# 并发跑多题时三个线程都会 emit，不加锁会出现两行 JSON 首尾粘在一起，
# 容器日志被切坏就没法用来复盘。
_emit_lock = threading.Lock()
_log_file: TextIO | None = None


def set_sink(sink: Sink | None) -> None:
    global _sink
    _sink = sink


def get_sink() -> Sink | None:
    return _sink


def set_log_file(path: str | None) -> None:
    """把事件流同时追加到文件，一行一个 JSON。path=None 表示关掉。"""
    global _log_file
    with _emit_lock:
        if _log_file is not None:
            try:
                _log_file.close()
            except Exception:
                pass
            _log_file = None
        if not path:
            return
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        _log_file = open(path, "a", encoding="utf-8")


def get_log_file() -> str | None:
    return getattr(_log_file, "name", None) if _log_file is not None else None


def emit(event: str, **payload: Any) -> dict[str, Any]:
    record: dict[str, Any] = {"event": event, **payload}
    sink = _sink
    if sink is not None:
        sink(record)
    else:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        line = json.dumps(record, ensure_ascii=False, default=str)
        with _emit_lock:
            print(line, flush=True)
    with _emit_lock:
        if _log_file is not None:
            try:
                _log_file.write(json.dumps(record, ensure_ascii=False,
                                           default=str) + "\n")
                _log_file.flush()
            except Exception:
                pass
    return record
