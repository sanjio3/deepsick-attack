"""每题一个工作区：笔记 / 规划待办 / 证据，全部落盘。

这是 artex「状态外置，不靠上下文」的最小实现。模型通过工具读写这三个
位置，上下文被 GC 掉之后它们还在：

- notes.md    过程黑板：只追加。每轮的关键观察由模型自己决定记什么——
              artex 的提示词原话是「记下来的才算数，活在脑子里的不算」。
- todolist.md 规划待办：跨轮共享。串行利用链（注入 → 拿凭据 → 横向 →
              提权）在这里只写一次，后续轮次按依赖逐步推进。
- evidence/   证据目录：文件名 = 步号-标签.txt，finding 必须挂证据才作数。

工作区根目录固定在 /tmp/ws/<unique_code>/，路径校验防逃逸。
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

_SAFE = re.compile(r"[^A-Za-z0-9_.\-]")
MAX_NOTE_APPEND = 8000
MAX_READ_CHARS = 6000


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        (self.root / "evidence").mkdir(parents=True, exist_ok=True)
        notes = self.root / "notes.md"
        if not notes.exists():
            notes.write_text("# 工作笔记\n\n", encoding="utf-8")
        todo = self.root / "todolist.md"
        if not todo.exists():
            todo.write_text(
                "# 规划待办（跨轮共享，按依赖推进）\n\n"
                "<!-- 格式：- [ ] 步骤（前置：xxx）｜ - [x] 已完成｜ - [!] 被封锁（依据） -->\n",
                encoding="utf-8")

    # ---- 路径安全 ----
    def _resolve(self, rel: str) -> Path:
        rel = (rel or "").strip().lstrip("/")
        if not rel:
            rel = "notes.md"
        target = (self.root / rel).resolve()
        root = self.root.resolve()
        if not str(target).startswith(str(root) + os.sep):
            raise ValueError(f"路径越界：{rel}")
        if target.suffix not in (".md", ".txt", ".json", ".log", ""):
            raise ValueError(f"只允许读写文本类文件：{rel}")
        return target

    # ---- notes.md：追加式黑板 ----
    def append_note(self, text: str) -> str:
        text = (text or "").strip()
        if not text:
            return "（空笔记未写入）"
        stamp = time.strftime("%H:%M:%S")
        if len(text) > MAX_NOTE_APPEND:
            text = text[:MAX_NOTE_APPEND] + "\n…(截断)"
        with open(self.root / "notes.md", "a", encoding="utf-8") as fh:
            fh.write(f"\n## {stamp}\n{text}\n")
        return f"已写入 notes.md（累计 {self.note_size()} 字符）"

    def read_note(self) -> str:
        return self._read(self.root / "notes.md")

    def note_size(self) -> int:
        try:
            return (self.root / "notes.md").stat().st_size
        except OSError:
            return 0

    # ---- todolist.md：整读整写 ----
    def read_todo(self) -> str:
        return self._read(self.root / "todolist.md")

    def write_todo(self, text: str) -> str:
        text = (text or "").strip()
        if not text:
            return "（拒绝清空 todolist；要改就写全量新内容）"
        (self.root / "todolist.md").write_text(text + "\n", encoding="utf-8")
        return "todolist.md 已更新"

    # ---- 证据 ----
    def save_evidence(self, tag: str, content: str) -> str:
        tag = _SAFE.sub("-", (tag or "e").strip())[:40] or "e"
        path = self.root / "evidence" / f"{time.strftime('%H%M%S')}-{tag}.txt"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def evidence_list(self) -> list[str]:
        d = self.root / "evidence"
        return sorted(p.name for p in d.iterdir() if p.is_file())

    def read_evidence(self, name: str) -> str:
        return self._read(self._resolve(f"evidence/{name}"))

    def _read(self, path: Path) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "（文件不存在）"
        if len(text) > MAX_READ_CHARS:
            return text[:MAX_READ_CHARS] + f"\n…(截断，全文 {len(text)} 字符)"
        return text

    def read_file(self, rel: str) -> str:
        return self._read(self._resolve(rel))

    def write_file(self, rel: str, content: str) -> str:
        target = self._resolve(rel)
        if target == (self.root / "notes.md").resolve():
            return "notes.md 是追加式黑板，请用 append_note"
        content = content or ""
        if len(content) > 40000:
            content = content[:40000] + "\n…(截断)"
        target.write_text(content, encoding="utf-8")
        return f"已写入 {rel}（{len(content)} 字符）"
