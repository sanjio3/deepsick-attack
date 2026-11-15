"""事实板：把观测压缩成可推理的状态，而不是把最近 8 条原文塞进 prompt。

这是 Cairn 的 Fact/Intent/Hint、artex 的 goal/fact/evidence 在这里的落地形态。
原来的 solver 只在内存里存原始输出、每步只回灌最近 8 条（还截到 1100 字符），
结果是第 3 步发现的东西到第 10 步就丢了，40 步之后模型对全局一无所知。

落盘到 jsonl：容器被杀、进程重启、上下文被截断，状态都还在。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field

RISK_ORDER = {"low": 0, "suspicious": 1, "honeypot": 2}


@dataclass
class Fact:
    kind: str          # service / route / credential / tripwire / artifact / flag
    key: str           # 去重键
    detail: str        # 一句话事实
    risk: str = "low"
    step: int = 0

    def line(self) -> str:
        tag = {"service": "SVC", "route": "RTE", "credential": "CRED",
               "tripwire": "TRAP", "artifact": "ART", "flag": "FLAG"}.get(
                   self.kind, self.kind.upper()[:4])
        risk = "" if self.risk == "low" else f" risk={self.risk}"
        return f"{tag} {self.detail}{risk}"


class FactBoard:
    def __init__(self, path: str | None = None, host: str = ""):
        self.facts: list[Fact] = []
        self._keys: set[str] = set()
        self.tried: set[str] = set()
        self.failed: dict[str, int] = {}
        self.host = host
        self.path = path or os.path.join(
            "/tmp", f"facts-{int(time.time() * 1000)}.jsonl")
        self._restore()

    # -- 持久化 ----------------------------------------------------

    def _restore(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if row.get("_tried"):
                        self.tried.add(row["_tried"])
                        continue
                    fact = Fact(**row)
                    if fact.key not in self._keys:
                        self._keys.add(fact.key)
                        self.facts.append(fact)
        except (OSError, ValueError, TypeError):
            pass

    def _persist(self, row: dict) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError:
            pass

    # -- 写入 ------------------------------------------------------

    def add(self, fact: Fact) -> bool:
        if not fact.key or fact.key in self._keys:
            return False
        self._keys.add(fact.key)
        self.facts.append(fact)
        row = asdict(fact)
        self._persist(row)
        return True

    def mark_tried(self, key: str, ok: bool = True) -> None:
        if key in self.tried:
            return
        self.tried.add(key)
        self._persist({"_tried": key})
        if not ok:
            self.bump_failure(key)

    def bump_failure(self, key: str) -> int:
        self.failed[key] = self.failed.get(key, 0) + 1
        return self.failed[key]

    def flag_honeypot(self, key: str) -> None:
        """把某个服务标成高风险：后续候选生成会把它排到最后。"""
        for fact in self.facts:
            if fact.key == key and fact.risk != "honeypot":
                fact.risk = "honeypot"

    # -- 读 --------------------------------------------------------

    def of(self, kind: str) -> list[Fact]:
        return [f for f in self.facts if f.kind == kind]

    def services(self) -> list[Fact]:
        return self.of("service")

    def risky(self) -> set[str]:
        return {f.key for f in self.facts if f.risk == "honeypot"}

    def snapshot(self, limit: int = 24) -> str:
        """给模型看的态势摘要。按风险与类别排序，同 key 只出现一次。"""
        if not self.facts:
            return "（事实板为空，还没有任何探测结果）"
        groups: dict[str, list[Fact]] = {}
        for fact in self.facts:
            groups.setdefault(fact.kind, []).append(fact)
        order = ["service", "route", "credential", "tripwire", "artifact", "flag"]
        lines: list[str] = []
        for kind in order + [k for k in groups if k not in order]:
            rows = groups.get(kind) or []
            rows.sort(key=lambda f: -RISK_ORDER.get(f.risk, 0))
            for fact in rows[:limit]:
                lines.append(fact.line())
        if len(lines) > limit:
            lines = lines[:limit] + [f"...（另有 {len(lines) - limit} 条事实）"]
        return "\n".join(lines)

    def stats(self) -> dict:
        return {"facts": len(self.facts),
                "services": len(self.services()),
                "tried": len(self.tried),
                "risky": len(self.risky())}
