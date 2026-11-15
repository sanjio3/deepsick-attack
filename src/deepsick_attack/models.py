"""共享数据模型。

所有跨模块传递的对象集中在这里定义，避免模块之间循环导入。
每个模型都提供 to_dict()，保证落盘与前端事件使用同一套字段。
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


@dataclass
class Intent:
    id: str
    stage: str
    action: str
    status: str = "open"
    rationale: str = ""
    parent_ids: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    reopen_reason: str = ""
    ts: str = field(default_factory=_ts)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Fact:
    id: str
    intent_id: str
    summary: str
    detail: str
    confidence: str
    stage: str
    technique: str
    evidence_paths: list[str] = field(default_factory=list)
    ts: str = field(default_factory=_ts)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Hint:
    id: str
    stage: str
    text: str
    source: str
    ts: str = field(default_factory=_ts)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TraceStep:
    seq: int
    intent_id: str
    stage: str
    technique: str
    action: str
    tool: str
    observation_ref: str
    evidence_paths: list[str]
    verdicts: list[dict]
    fact_id: str
    path_points: float
    ts: str = field(default_factory=_ts)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExitVerdict:
    stage: str
    passed: bool
    detector: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Candidate:
    stage: str
    action: str
    prior: float
    rationale: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AlignmentResult:
    expected: list[str]
    actual: list[str]
    matched: list[str]
    coverage: float
    order_ratio: float
    skipped: int
    points: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RankedCandidate:
    candidate: Candidate
    score: float
    alignment_gain: float
    skipped_stages: int

    def to_dict(self) -> dict:
        return {
            "candidate": self.candidate.to_dict(),
            "score": round(self.score, 4),
            "alignment_gain": round(self.alignment_gain, 2),
            "skipped_stages": self.skipped_stages,
        }
