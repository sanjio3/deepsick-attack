"""探索图：goal → intent → fact → finding 的血缘链（artex 双图之二）。

资产图（attack_graph.py）回答「攻击面上有什么」，本图回答「每个方向测到
了什么程度」：

- intent  一个待验证的攻击假设，锚定到资产图的 entry key。状态机：
          pending → running → done / dead / blocked（blocked 等会话后可重开）。
- fact    一条被证据支撑的事实（某入口可读文件、某页有注入回显……），
          由某个 intent 产出，又可以派生新的 intent（derived_from 边）。
- finding 漏洞结论或 flag，必须挂 evidence 文件路径才作数（证据门控）。

全部状态 JSON 落盘到工作区，重启不丢；overview() 渲染成紧凑文本供
planner 读态势——planner 每次唤醒都从图上读，不从对话记忆里回忆。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

STATES = ("pending", "running", "done", "dead", "blocked")
FAMILIES = (
    "recon", "lfi", "sqli", "auth", "upload", "cmdi", "ssti", "ssrf",
    "deser", "crypto", "port", "web", "flag",
)


@dataclass
class Intent:
    id: int
    family: str
    target: str          # 资产图 entry key 或 host:port
    why: str
    status: str = "pending"
    step_created: int = 0
    step_closed: int = 0
    parent_fact: str = ""   # 派生自哪条 fact id
    verdict: str = ""       # 收口时的判定，dead 必须写依据
    evidence: list[str] = field(default_factory=list)


@dataclass
class Fact:
    id: str
    kind: str            # file_read / creds / session / injectable / ...
    content: str         # 压缩后的事实正文
    intent_id: int = 0
    step: int = 0
    evidence: str = ""


@dataclass
class Finding:
    id: str
    title: str
    evidence: str = ""
    flag: str = ""


class ExploreGraph:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.intents: list[Intent] = []
        self.facts: list[Fact] = []
        self.findings: list[Finding] = []
        self._next_id = 1
        self._fact_seq = 0
        if self.path.exists():
            self._load()

    # ---- 持久化 ----
    def save(self) -> None:
        data = {
            "intents": [i.__dict__ for i in self.intents],
            "facts": [f.__dict__ for f in self.facts],
            "findings": [f.__dict__ for f in self.findings],
            "next_id": self._next_id,
            "fact_seq": self._fact_seq,
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.intents = [Intent(**d) for d in data.get("intents", [])]
        self.facts = [Fact(**d) for d in data.get("facts", [])]
        self.findings = [Finding(**d) for d in data.get("findings", [])]
        self._next_id = int(data.get("next_id", 1))
        self._fact_seq = int(data.get("fact_seq", 0))

    # ---- intent 生命周期 ----
    def add_intent(self, family: str, target: str, why: str,
                   parent_fact: str = "", step: int = 0) -> Intent:
        fam = family if family in FAMILIES else "web"
        intent = Intent(id=self._next_id, family=fam, target=target[:120],
                        why=why[:300], parent_fact=parent_fact, step_created=step)
        self._next_id += 1
        self.intents.append(intent)
        self.save()
        return intent

    def claim(self, hint_family: str = "") -> Intent | None:
        """按优先级领一条：pending 里优先与 hint 同族、时间早的。"""
        pool = [i for i in self.intents if i.status == "pending"]
        if not pool:
            return None
        pool.sort(key=lambda i: (0 if (hint_family and i.family == hint_family)
                                 else 1, i.id))
        pool[0].status = "running"
        self.save()
        return pool[0]

    def close(self, intent_id: int, status: str, verdict: str = "",
              evidence: list[str] | None = None, step: int = 0) -> Intent | None:
        if status not in ("done", "dead", "blocked", "pending"):
            return None
        intent = next((i for i in self.intents if i.id == intent_id), None)
        if intent is None:
            return None
        intent.status = status
        intent.verdict = verdict[:400]
        intent.step_closed = step
        if evidence:
            intent.evidence = list(evidence)[:5]
        self.save()
        return intent

    def reopen_by_auth(self) -> int:
        """登录态更新后，把因权限被封锁的 intent 重开。"""
        n = 0
        for i in self.intents:
            if i.status == "blocked":
                i.status = "pending"
                i.verdict = (i.verdict + "｜会话已更新，重开").strip("｜")
                n += 1
        if n:
            self.save()
        return n

    def intents_for(self, target_key: str) -> list[Intent]:
        return [i for i in self.intents
                if i.target == target_key and i.status in ("pending", "running")]

    def intents_pending(self) -> bool:
        return any(i.status in ("pending", "running") for i in self.intents)

    # ---- fact / finding ----
    def add_fact(self, kind: str, content: str, intent_id: int = 0,
                 step: int = 0, evidence: str = "") -> Fact:
        self._fact_seq += 1
        fact = Fact(id=f"f{self._fact_seq}", kind=kind,
                    content=content[:500], intent_id=intent_id,
                    step=step, evidence=evidence)
        self.facts.append(fact)
        self.save()
        return fact

    def add_finding(self, title: str, evidence: str = "", flag: str = "") -> Finding:
        self._fact_seq += 1
        finding = Finding(id=f"fd{self._fact_seq}", title=title[:300],
                          evidence=evidence, flag=flag)
        self.findings.append(finding)
        self.save()
        return finding

    def has_flag(self, flag: str) -> bool:
        return any(f.flag == flag for f in self.findings)

    # ---- 态势渲染 ----
    def overview(self, asset_line: str = "", limit: int = 24) -> str:
        lines = ["== 探索图（intent/fact/finding）=="]
        if asset_line:
            lines.append(asset_line)
        todo = [i for i in self.intents if i.status in ("pending", "running")]
        done = [i for i in self.intents if i.status == "done"]
        dead = [i for i in self.intents if i.status in ("dead", "blocked")]
        if todo:
            lines.append("— 待验证 / 进行中 —")
            for i in todo[:limit]:
                tag = "▶" if i.status == "running" else "·"
                lines.append(f"{tag} #{i.id} [{i.family}] {i.target} — {i.why}")
        else:
            lines.append("— 没有待验证的意图：作为 planner，你应该从事实里派生新方向 —")
        if done:
            lines.append("— 已完成（取前 8 条）—")
            for i in done[:8]:
                lines.append(f"✓ #{i.id} [{i.family}] {i.target} — "
                             f"{i.verdict[:80]}")
        if dead:
            lines.append(f"— 封锁 {len(dead)} 条（重开必须写新机理）—")
            for i in dead[:6]:
                lines.append(f"✗ #{i.id} [{i.family}] {i.target} — "
                             f"{i.verdict[:70]}")
        if self.facts:
            lines.append("— 事实（血缘：intent → fact → 新 intent）—")
            for f in self.facts[-12:]:
                src = f"#{f.intent_id}" if f.intent_id else "recon"
                ev = f" [证:{os.path.basename(f.evidence)}]" if f.evidence else ""
                lines.append(f"* {f.id}({f.kind}, from {src}){ev} "
                             f"{f.content[:110]}")
        if self.findings:
            lines.append("— 发现 —")
            for f in self.findings[-8:]:
                lines.append(f"! {f.id} {f.title[:100]}"
                             + (f" flag={f.flag[:60]}" if f.flag else ""))
        return "\n".join(lines)

    def stats(self) -> dict:
        return {
            "intents": len(self.intents),
            "pending": sum(1 for i in self.intents if i.status == "pending"),
            "dead": sum(1 for i in self.intents if i.status == "dead"),
            "facts": len(self.facts),
            "findings": len(self.findings),
        }


def now_stamp() -> str:
    return time.strftime("%H:%M:%S")
