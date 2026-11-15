"""主办方标准路径的可执行编码。

前提：官方路径就是最优解，不做全局路径搜索。本模块做三件事：
按剧本一次推进一个阶段、为每阶段配 garak 式退出判据、
判据未过时只在当前阶段 fallbacks 内换手段（Cairn 式局部搜索）。
"""
from __future__ import annotations

import re

from .models import ExitVerdict


class StageRunner:
    def __init__(self, policy: dict):
        self.path = policy["official_path"]
        self.ids = [stage["id"] for stage in self.path]
        self.fallback_limit = int(policy.get("fallback_limit", 2))
        self.flag_regex = policy["flag_regex"]
        self.hints = {h["stage"]: h["text"] for h in policy["playbook_hints"]}

    def current(self, trace: list[dict]):
        """返回第一个尚未由 stage_exit 判定通过的阶段；全部通过返回 None。"""
        passed: set[str] = set()
        for step in trace:
            for verdict in step.get("verdicts", []):
                if verdict.get("name") == "stage_exit" and verdict.get("passed"):
                    passed.add(step["stage"])
        for stage in self.path:
            if stage["id"] not in passed:
                return stage
        return None

    def check_exit(self, stage: dict, observation_text: str,
                   source_kind: str) -> ExitVerdict:
        """garak 式 detector：只看真实工具输出，不看模型自述。"""
        sid = stage["id"]
        if source_kind != "tool_output":
            return ExitVerdict(sid, False, "source", "非工具输出，不采信")
        criteria = stage["exit_criteria"]
        kind = criteria["detector"]
        text = observation_text or ""
        if kind == "contains_any":
            hit = next((t for t in criteria["tokens"] if t in text), None)
            return ExitVerdict(
                sid, bool(hit), kind,
                f"退出判据命中 '{hit}'" if hit else "响应未包含任一判据 token",
            )
        if kind == "flag":
            match = re.search(self.flag_regex, text)
            return ExitVerdict(
                sid, bool(match), kind,
                f"退出判据命中 {match.group(0)}" if match else "响应中无 Flag",
            )
        return ExitVerdict(sid, False, kind, f"未知 detector 类型 {kind}")

    def next_action(self, stage: dict, attempt_no: int):
        """第 0 次用标准动作，之后只在本阶段 fallbacks 里取，用完返回 None。"""
        if attempt_no == 0:
            return stage["action"]
        fallbacks = stage.get("fallbacks", [])
        idx = attempt_no - 1
        if idx < len(fallbacks) and idx < self.fallback_limit:
            return fallbacks[idx]
        return None

    def hint_for(self, stage_id: str) -> str:
        return self.hints.get(stage_id, "")

    def deviation(self, trace_stages, matcher) -> dict:
        """复用 LCS 对齐，把路径匹配度当验收指标算出来。"""
        result = matcher.align(trace_stages)
        return {
            "points": result.points,
            "coverage": result.coverage,
            "missing": [s for s in self.ids if s not in result.actual],
            "matched": result.matched,
        }
