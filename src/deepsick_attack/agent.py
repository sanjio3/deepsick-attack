"""主循环：按主办方标准路径逐阶段取证的串行攻击 Agent。

官方路径即最优解，因此不做全局路径搜索。主干是确定性剧本执行，
只在单个阶段的标准动作失败时，借 Cairn 式局部搜索换备选手段。

四个机制：
- artex  -> blackboard.py 血缘 + verifiers.py 反伪完成清单
- Cairn  -> stage_runner.py 阶段内 fallbacks + HintEngine 自动注入
- CAI    -> prompts/auditor.md 异构复核，替代人在环路
- garak  -> stage_runner.check_exit 退出判据 + trace.jsonl 逐次留痕
"""
from __future__ import annotations

from pathlib import Path

from .backends import HintEngine, OfflineExecutor, OfflineLLM
from .blackboard import Blackboard
from .config import technique_map
from .events import emit
from .models import Candidate, Fact, Intent, TraceStep, Verdict
from .path_score import PathMatcher
from .stage_runner import StageRunner
from .verifiers import (
    anti_false_completion,
    exploit_provenance,
    flag_detector,
    scope_guard,
    stage_detector,
)


def append_step(bb, matcher, intent, verdicts, evidence_paths, fact_id, techniques):
    state = bb.load_state()
    seq = len(state["trace"]) + 1
    new_stages = [step["stage"] for step in state["trace"]] + [intent.stage]
    points = matcher.align(new_stages).points
    step = TraceStep(
        seq=seq,
        intent_id=intent.id,
        stage=intent.stage,
        technique=techniques.get(intent.stage, ""),
        action=intent.action,
        tool=intent.action.split(":")[0] if ":" in intent.action else "executor",
        observation_ref=evidence_paths[0] if evidence_paths else "",
        evidence_paths=evidence_paths,
        verdicts=[verdict.to_dict() for verdict in verdicts],
        fact_id=fact_id,
        path_points=points,
    )
    bb.append_trace(step)
    emit(
        "step",
        seq=seq,
        stage=intent.stage,
        action=intent.action,
        stage_exit=any(v.name == "stage_exit" and v.passed for v in verdicts),
        path_points=points,
    )
    return step


def close_intent(bb, intent: Intent) -> None:
    bb.add_intent(Intent(
        id=intent.id, stage=intent.stage, action=intent.action,
        status="done", rationale=intent.rationale,
    ))


def run_target(target_id: int, policy: dict, workspace: str | Path,
               max_steps: int = 24, inject_failure: str | None = None) -> dict:
    runner = StageRunner(policy)
    matcher = PathMatcher(
        runner.ids,
        policy["competition"]["path_points_per_target"],
        policy["score_weights"],
        policy["path_formula"],
    )
    techniques = technique_map(policy)
    allowlist = policy["scope_allowlist"]
    address = allowlist[(target_id - 1) % len(allowlist)]
    bb = Blackboard(workspace, target_id)
    llm = OfflineLLM()
    executor = OfflineExecutor(fail_once_on=inject_failure)
    hint_engine = HintEngine(runner)

    flag_value = None
    result = {
        "target": target_id,
        "flag": None,
        "flag_points": 0,
        "path_points": 0.0,
        "total_points": 0,
        "steps": 0,
        "proved": False,
        "checks": [],
    }
    emit(
        "run_start",
        target=target_id,
        address=address,
        official_path=runner.ids,
        no_human_in_loop=policy["competition"]["no_human_in_loop"],
        inject_failure=inject_failure,
        note="离线执行后端，正式赛场需替换为真实工具执行器",
    )

    current_stage = None
    attempt_no = 0
    exhaust: dict[str, int] = {}

    for step_no in range(1, max_steps + 1):
        state = bb.load_state()
        if current_stage is None:
            current_stage = runner.current(state["trace"])
            attempt_no = 0
            if current_stage is None:
                break
            emit(
                "stage_enter",
                stage=current_stage["id"],
                label=current_stage["label"],
                standard_action=current_stage["action"],
            )

        stage = current_stage
        action = runner.next_action(stage, attempt_no)
        if action is None:
            count = exhaust.get(stage["id"], 0) + 1
            exhaust[stage["id"]] = count
            hint = hint_engine.inject(stage["id"], state)
            if hint:
                bb.add_hint(hint)
                emit("hint_injected", stage=hint.stage, text=hint.text,
                     source=hint.source)
            emit("fallbacks_exhausted", stage=stage["id"], count=count)
            if count > 2:
                emit("stage_blocked", stage=stage["id"],
                     reason="本阶段备选手段用尽，封锁且不跨阶段跳步")
                break
            attempt_no = 0
            continue

        command = llm.propose_action(stage, action, state)
        intent = Intent(
            id=f"i{step_no}",
            stage=stage["id"],
            action=command,
            status="running",
            rationale=f"official_path {stage['id']} attempt {attempt_no}",
        )
        bb.add_intent(intent)

        observation = executor.execute(intent)
        evidence = bb.write_evidence(
            f"{intent.id}-{stage['id']}",
            observation["command"], observation["output"],
        )
        exit_v = runner.check_exit(
            stage, observation["output"], observation["source_kind"]
        )
        found, v_flag = flag_detector(
            observation["output"], observation["source_kind"], policy
        )
        verdicts = [
            scope_guard(address, policy),
            stage_detector(stage["id"], policy),
            v_flag,
            Verdict("stage_exit", exit_v.passed, exit_v.detail),
        ]
        fact_id = f"f{step_no}"
        append_step(bb, matcher, intent, verdicts, [evidence], fact_id, techniques)
        bb.add_fact(Fact(
            id=fact_id,
            intent_id=intent.id,
            summary=f"{stage['label']} {'完成' if exit_v.passed else '未通过'}",
            detail=observation["output"],
            confidence="observed" if exit_v.passed else "inferred",
            stage=stage["id"],
            technique=techniques.get(stage["id"], ""),
            evidence_paths=[evidence],
        ))
        close_intent(bb, intent)
        emit(
            "attempt",
            seq=step_no, stage=stage["id"], action=command,
            attempt_no=attempt_no, stage_exit=exit_v.passed,
            detail=exit_v.detail, evidence=evidence,
        )

        if not exit_v.passed:
            attempt_no += 1
            continue

        if stage["id"] == "flag" and found:
            flag_value = found
            replay = Intent(
                id=f"i{step_no}-replay",
                stage=stage["id"],
                action=command + ":independent_replay",
                status="running",
                rationale="CAI 异构复核：不同命令独立复现",
            )
            bb.add_intent(replay)
            obs2 = executor.execute(replay, replay=True)
            evidence2 = bb.write_evidence(
                f"{replay.id}-{replay.stage}", obs2["command"], obs2["output"]
            )
            _, v_flag2 = flag_detector(
                obs2["output"], obs2["source_kind"], policy
            )
            exit_v2 = runner.check_exit(
                stage, obs2["output"], obs2["source_kind"]
            )
            append_step(
                bb, matcher, replay,
                [scope_guard(address, policy),
                 stage_detector(replay.stage, policy),
                 v_flag2,
                 Verdict("stage_exit", exit_v2.passed, exit_v2.detail)],
                [evidence2], fact_id, techniques,
            )
            close_intent(bb, replay)
            emit("independent_replay", stage=replay.stage, action=replay.action,
                 passed=exit_v2.passed, evidence=evidence2)

        current_stage = None
        attempt_no = 0

    state = bb.load_state()
    stages = [step["stage"] for step in state["trace"]]
    result["steps"] = len(stages)
    result["path_points"] = matcher.align(stages).points

    if runner.current(state["trace"]) is None and flag_value:
        ok, checks = anti_false_completion(state, policy, flag_value)
        provenance = exploit_provenance(state, policy)
        shortcut_ok, shortcut_note = matcher.shortcut_guard(stages)
        deviation = runner.deviation(stages, matcher)
        proved = ok and provenance.passed and shortcut_ok and not deviation["missing"]
        result["checks"] = checks
        result["proved"] = proved
        emit(
            "goal_check",
            anti_false_completion=checks,
            exploit_provenance=provenance.to_dict(),
            shortcut_guard={"passed": shortcut_ok, "detail": shortcut_note},
            deviation=deviation,
            proved=proved,
        )
        if proved:
            result["flag"] = flag_value
            result["flag_points"] = policy["competition"]["flag_points"]
            result["total_points"] = result["flag_points"] + result["path_points"]
            emit("goal_proved", **result)

    if not result["proved"]:
        emit("run_stopped_without_proof", **result)
    return result


def self_test(policy: dict, workspace: str | Path) -> dict:
    """离线自检：不发起真实网络请求，验证剧本执行与失败兜底。"""
    runner = StageRunner(policy)
    matcher = PathMatcher(
        runner.ids,
        policy["competition"]["path_points_per_target"],
        policy["score_weights"],
        policy["path_formula"],
    )

    shortcut = ["recon", "flag"]
    a = matcher.align(shortcut)
    b = matcher.align(runner.ids)
    emit(
        "alignment_demo",
        shortcut={"stages": shortcut, "path_points": a.points,
                  "total": 200 + a.points, "skipped": a.skipped},
        standard={"stages": runner.ids, "path_points": b.points,
                  "total": 200 + b.points, "skipped": b.skipped},
    )

    ranked = matcher.rank([
        Candidate("fingerprint", "do_fingerprint", 0.80, "按标准推进"),
        Candidate("flag", "jump_to_flag", 0.95, "直接拿 Flag"),
    ], ["recon"])
    emit("ranking_demo",
         note="仅用于阶段内候选排序；全局选步由 official_path 决定",
         ranked=[item.to_dict() for item in ranked])

    hint = HintEngine(runner).inject("fingerprint", {"hints": []})
    emit("hint_demo", auto_injected=hint.to_dict() if hint else None)

    normal = run_target(1, policy, workspace, max_steps=24)
    with_failure = run_target(
        2, policy, workspace, max_steps=24, inject_failure="fingerprint"
    )
    summary = {
        "normal": {k: normal[k] for k in
                   ("steps", "path_points", "total_points", "proved")},
        "with_failure": {k: with_failure[k] for k in
                         ("steps", "path_points", "total_points", "proved")},
        "note": "注入一次阶段失败后仍按剧本走完，未跨阶段跳步",
    }
    emit("self_test_summary", **summary)
    emit("manifest", deliverable=policy["deliverable"], entry="SKILL.md",
         trajectory=str(Path(workspace) / "target_1" / "trace.jsonl"),
         no_human_in_loop=True)
    return summary
