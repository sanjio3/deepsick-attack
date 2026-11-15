"""结构化事件输出。

所有运行状态都通过 emit 往外推，不在后台静默执行。默认输出到 stdout，
前端可以调用 set_sink 接管事件流，测试也可以注入收集器避免污染输出。
"""
from __future__ import annotations

import json
import sys
import threading
from typing import Any, Callable

Sink = Callable[[dict[str, Any]], None]
_sink: Sink | None = None
# 并发跑多题时三个线程都会 emit，不加锁会出现两行 JSON 首尾粘在一起，
# 容器日志被切坏就没法用来复盘。
_emit_lock = threading.Lock()


def set_sink(sink: Sink | None) -> None:
    global _sink
    _sink = sink


def get_sink() -> Sink | None:
    return _sink


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
    return record
