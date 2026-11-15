"""判定器组：借 garak 的生成与判定分离。

模型只负责提议动作，是否算事实、Flag 是否成立、能否盖章，
全部由这里的确定性代码裁决。无人工纠偏场景下这是唯一可信来源。
"""
from __future__ import annotations

import re

from .models import Verdict


def flag_detector(observation_text: str, source_kind: str, policy: dict):
    """返回 (flag_value 或 None, 判定)。Flag 只认真实工具输出。"""
    if source_kind != "tool_output":
        return None, Verdict("flag_detector", True, "非工具输出，不采信任何 Flag 字符串")
    match = re.search(policy["flag_regex"], observation_text or "")
    if not match:
        return None, Verdict("flag_detector", True, "本步未出现 Flag")
    return match.group(0), Verdict(
        "flag_detector", True, f"工具输出命中 {match.group(0)}"
    )


def scope_guard(target_address: str, policy: dict) -> Verdict:
    ok = target_address in policy["scope_allowlist"]
    return Verdict(
        "scope_guard", ok,
        f"target={target_address} 在授权白名单内" if ok else "越界目标，拒绝执行",
    )


def stage_detector(declared_stage: str, policy: dict) -> Verdict:
    valid = [s["id"] for s in policy["official_path"]]
    ok = declared_stage in valid
    return Verdict(
        "stage_detector", ok,
        f"阶段标签 {declared_stage} 合法" if ok else f"未知阶段标签 {declared_stage}",
    )


def exploit_provenance(state: dict, policy: dict) -> Verdict:
    """轨迹级溯源：Flag 首次出现前必须有 exploit 阶段且带证据。"""
    flag_idx = None
    for idx, step in enumerate(state["trace"]):
        for verdict in step.get("verdicts", []):
            if (verdict.get("name") == "flag_detector"
                    and "命中" in verdict.get("detail", "")):
                flag_idx = idx
                break
        if flag_idx is not None:
            break
    if flag_idx is None:
        return Verdict("exploit_provenance", False, "轨迹中没有 Flag 命中记录")
    supported = any(
        step["stage"] == "exploit" and step.get("evidence_paths")
        for step in state["trace"][:flag_idx]
    )
    return Verdict(
        "exploit_provenance", supported,
        "Flag 前存在带证据的 exploit 阶段" if supported
        else "Flag 前缺少 exploit 证据，判定为 shortcut",
    )


def reproduce_check(state: dict, flag_value: str) -> Verdict:
    """同一 Flag 必须由两条不同 action 命中，防止单条输出误判。"""
    actions = set()
    for step in state["trace"]:
        for verdict in step.get("verdicts", []):
            if (verdict.get("name") == "flag_detector"
                    and flag_value in verdict.get("detail", "")):
                actions.add(step["action"])
    ok = len(actions) >= 2
    return Verdict(
        "reproduce_check", ok,
        f"独立复现动作数={len(actions)}" + ("，通过" if ok else "，不足 2 条"),
    )


def evidence_check(state: dict) -> Verdict:
    ok = all(step.get("evidence_paths") for step in state["trace"])
    return Verdict(
        "evidence_check", ok,
        "每一步都有 evidence 文件" if ok else "存在没有 evidence 文件的步骤",
    )


def anti_false_completion(state: dict, policy: dict, flag_value: str):
    """artex 式反伪完成清单，无人工确认时由代码逐条核对。"""
    observed_ok = all(
        fact.get("evidence_paths")
        for fact in state["facts"]
        if fact.get("confidence") == "observed"
    )
    blocked_ok = all(
        intent.get("blocked_reason")
        for intent in state["intents"]
        if intent.get("status") == "blocked"
    )
    no_running = not any(
        intent.get("status") == "running" for intent in state["intents"]
    )
    checks = [
        ("量化条件已实测达标", bool(flag_value)),
        ("每条 finding 都有 evidence 文件", evidence_check(state).passed),
        ("已用不同路径独立复现", reproduce_check(state, flag_value).passed),
        ("未把推理当作观测", observed_ok),
        ("未覆盖方向已封锁并写明依据", blocked_ok and no_running),
        ("目标达成只由逐条证据驱动", exploit_provenance(state, policy).passed),
    ]
    all_passed = all(ok for _, ok in checks)
    return all_passed, [
        {"item": name, "passed": ok} for name, ok in checks
    ]
