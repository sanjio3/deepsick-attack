"""攻击路径匹配度的对齐计算与偏离检测。

前提：主办方给出的标准路径就是最优解，因此本模块的角色是验收指标，
不是搜索目标函数。主干由 stage_runner.py 按剧本推进。

对外提供三件事：align 算 40 分、cursor 与 shortcut_guard 做偏离检测、
rank 仅用于单阶段内部对候选手段排序。
"""
from __future__ import annotations

from typing import Sequence

from .models import AlignmentResult, Candidate, RankedCandidate


def dedupe(seq: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def lcs(a: Sequence[str], b: Sequence[str]) -> list[str]:
    """最长公共子序列：同时表达阶段覆盖率与先后顺序。"""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    i, j, out = n, m, []
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            out.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return list(reversed(out))


class PathMatcher:
    def __init__(self, stage_ids, max_points=40.0, weights=None, formula=None):
        self.stage_ids = list(stage_ids)
        self.max_points = float(max_points)
        self.weights = weights or {"alpha": 1.0, "beta": 1.2, "gamma": 0.8}
        self.formula = formula or {
            "coverage_weight": 0.7,
            "order_weight": 0.3,
            "skip_penalty": 0.5,
        }

    def align(self, trace_stages) -> AlignmentResult:
        expected = self.stage_ids
        actual = dedupe(trace_stages)
        matched = lcs(expected, actual)
        coverage = len(matched) / max(1, len(expected))
        order_ratio = len(matched) / max(1, len(actual))
        skipped = len([s for s in expected if s not in actual])
        raw = (self.formula["coverage_weight"] * coverage
               + self.formula["order_weight"] * order_ratio)
        penalty = self.formula["skip_penalty"] * (skipped / max(1, len(expected)))
        points = round(self.max_points * max(0.0, raw - penalty), 2)
        return AlignmentResult(
            expected=list(expected),
            actual=actual,
            matched=matched,
            coverage=round(coverage, 4),
            order_ratio=round(order_ratio, 4),
            skipped=skipped,
            points=points,
        )

    def cursor(self, trace_stages) -> int:
        """下一个应当推进的标准阶段下标。"""
        actual = set(dedupe(trace_stages))
        for idx, stage in enumerate(self.stage_ids):
            if stage not in actual:
                return idx
        return len(self.stage_ids) - 1

    def rank(self, candidates, trace_stages) -> list[RankedCandidate]:
        """仅用于阶段内候选排序：score = a*prior + b*增益 - g*跳步。"""
        base = self.align(trace_stages).points
        cursor = self.cursor(trace_stages)
        total = max(1, len(self.stage_ids))
        ranked: list[RankedCandidate] = []
        for cand in candidates:
            idx = (
                self.stage_ids.index(cand.stage)
                if cand.stage in self.stage_ids else total
            )
            skipped = max(0, idx - cursor - 1)
            gain = self.align(list(trace_stages) + [cand.stage]).points - base
            score = (self.weights["alpha"] * cand.prior
                     + self.weights["beta"] * (gain / max(1.0, self.max_points))
                     - self.weights["gamma"] * (skipped / total))
            ranked.append(RankedCandidate(cand, score, gain, skipped))
        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked

    def shortcut_guard(self, trace_stages, flag_stage="flag") -> tuple[bool, str]:
        """Flag 出现前若缺利用阶段，要求回补证据而不是直接提交。"""
        if flag_stage not in trace_stages:
            return True, "尚未出现 Flag"
        pos = list(trace_stages).index(flag_stage)
        before = list(trace_stages)[:pos]
        if "exploit" in self.stage_ids and "exploit" not in before:
            return False, "Flag 前缺少 exploit 阶段，判定为 shortcut，必须回补证据"
        return True, "Flag 由前置利用阶段支撑"
