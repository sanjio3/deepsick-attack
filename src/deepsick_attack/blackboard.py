"""状态外置黑板。

借自 artex 的 goal / intent / fact / finding / evidence 落库机制与
Cairn 的 Fact / Intent / Hint 三原语，改成零依赖的文件黑板。

所有结论必须落盘才算数。上下文被压缩或进程重启后从文件恢复，
每个靶标一个独立目录，互不共享凭据文件。
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Fact, Hint, Intent, TraceStep

FILES = ("intents.jsonl", "facts.jsonl", "hints.jsonl", "trace.jsonl")


class Blackboard:
    def __init__(self, workspace: str | Path, target_id: int):
        self.root = Path(workspace) / f"target_{target_id}"
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "evidence").mkdir(exist_ok=True)
        for name in FILES:
            path = self.root / name
            if not path.exists():
                path.write_text("", encoding="utf-8")
        cred = self.root / "LIVE_CRED.txt"
        if not cred.exists():
            cred.write_text("", encoding="utf-8")

    def _append(self, name: str, obj) -> None:
        with (self.root / name).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(obj.to_dict(), ensure_ascii=False) + "\n")

    def _read(self, name: str) -> list[dict]:
        path = self.root / name
        if not path.exists():
            return []
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows

    def add_intent(self, intent: Intent) -> None:
        self._append("intents.jsonl", intent)

    def add_fact(self, fact: Fact) -> None:
        self._append("facts.jsonl", fact)

    def add_hint(self, hint: Hint) -> None:
        self._append("hints.jsonl", hint)

    def append_trace(self, step: TraceStep) -> None:
        self._append("trace.jsonl", step)

    def write_evidence(self, step_key: str, command: str, output: str) -> str:
        """原始输出不加工、不截断，命令原文与完整响应一起落盘。"""
        safe = "".join(
            ch if ch.isalnum() or ch in "-_" else "_" for ch in step_key
        )
        path = self.root / "evidence" / f"{safe}.txt"
        path.write_text(
            "COMMAND:\n" + command + "\n\nOUTPUT:\n" + output + "\n",
            encoding="utf-8",
        )
        return str(path)

    def load_state(self) -> dict:
        # intent 是事件溯源写法：同一 id 追加新状态，取最后一条为当前状态。
        latest: dict[str, dict] = {}
        for intent in self._read("intents.jsonl"):
            latest[intent["id"]] = intent
        return {
            "intents": list(latest.values()),
            "facts": self._read("facts.jsonl"),
            "hints": self._read("hints.jsonl"),
            "trace": self._read("trace.jsonl"),
        }

    def snapshot_text(self, limit: int = 8) -> str:
        """交给 planner 的态势快照。planner 只读文件，不靠对话回忆。"""
        state = self.load_state()
        lines = [
            f"facts={len(state['facts'])} intents={len(state['intents'])} "
            f"trace={len(state['trace'])} hints={len(state['hints'])}"
        ]
        for fact in state["facts"][-limit:]:
            lines.append(f"FACT {fact['id']} [{fact['confidence']}] {fact['summary']}")
        for step in state["trace"][-limit:]:
            lines.append(
                f"STEP {step['seq']} {step['stage']} {step['action']} "
                f"path={step['path_points']}"
            )
        for hint in state["hints"][-limit:]:
            lines.append(f"HINT [{hint['stage']}] {hint['text']}")
        return "\n".join(lines)
