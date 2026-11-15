"""结构化事件输出。

所有运行状态都通过 emit 往外推，不在后台静默执行。默认输出到 stdout，
前端可以调用 set_sink 接管事件流，测试也可以注入收集器避免污染输出。
"""
from __future__ import annotations

import json
import sys
from typing import Any, Callable

Sink = Callable[[dict[str, Any]], None]
_sink: Sink | None = None


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
        print(json.dumps(record, ensure_ascii=False, default=str), flush=True)
    return record
