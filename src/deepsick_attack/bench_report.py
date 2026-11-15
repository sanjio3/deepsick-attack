"""把本地跑出来的事件日志整理成按题聚合的诊断表。

本地 Agent 模式没有平台侧会话回放，`--log-file` 落下的 jsonl 是唯一的原始材料。
直接 grep 也能看，但一场跑分几万行，人工翻不现实。这里把它收成「每道题：用了几步、
卡在哪、试过哪些族、拿到了几个 flag」，对着表就能判断下一轮该改哪里。
"""
from __future__ import annotations

import json
from collections import OrderedDict

STEP_EVENTS = ("solve_step", "solve_repeat_blocked", "solve_stuck_hint",
               "solve_abandon", "solve_tripwire", "solve_submit",
               "solve_flag_found", "solve_breaker", "solve_done",
               "solve_bad_action", "solve_bad_action_giveup")


def load(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def summarize(path: str, tail: int = 2) -> "OrderedDict[str, dict]":
    """按 unique_code 聚合。返回有序字典，方便直接打印。"""
    per: "OrderedDict[str, dict]" = OrderedDict()
    for row in load(path):
        code = row.get("unique_code")
        if not code:
            continue
        item = per.setdefault(code, {
            "passes": set(), "steps": 0, "blocked": 0, "stuck": 0,
            "abandoned": False, "tripwires": 0, "breaker": False,
            "submitted": 0, "correct": 0, "bad_action": 0,
            "excluded": [], "last": [], "thoughts": [],
        })
        event = row.get("event", "")
        if event == "bench_started":
            item["passes"].add(row.get("pass_no", 1))
        elif event == "solve_step":
            item["steps"] += 1
            output = str(row.get("output") or "").replace("\n", " ")[:160]
            item["last"].append(f"步{row.get('step')} {row.get('tool')} "
                                f"→ {output}")
            item["last"] = item["last"][-(tail + 1):]
            thought = str(row.get("thought") or "")[:120]
            if thought:
                item["thoughts"].append(thought)
                item["thoughts"] = item["thoughts"][-3:]
        elif event == "solve_repeat_blocked":
            item["blocked"] += 1
        elif event == "solve_stuck_hint":
            item["stuck"] += 1
        elif event == "solve_abandon":
            item["abandoned"] = True
        elif event == "solve_tripwire":
            item["tripwires"] += 1
        elif event == "solve_breaker":
            item["breaker"] = True
        elif event == "solve_submit":
            item["submitted"] += 1
            if row.get("correct"):
                item["correct"] += 1
        elif event == "solve_flag_found":
            item["submitted"] += 1
            item["correct"] += 1
        elif event in ("solve_bad_action", "solve_bad_action_giveup"):
            item["bad_action"] += 1
        elif event == "solve_excluded":
            item["excluded"].append(str(row.get("key") or ""))
    for item in per.values():
        item["passes"] = sorted(item["passes"])
    return per


def render(path: str) -> str:
    """渲染成纯文本表。不用 markdown 表格，终端里直接看。"""
    per = summarize(path)
    if not per:
        return f"{path} 里没有可聚合的解题事件"
    lines = [f"{path}", f"共 {len(per)} 道题"]
    for code, item in per.items():
        head = (f"\n[{code}] 轮次={item['passes'] or '-'} 步数={item['steps']} "
                f"提交={item['submitted']} 正确={item['correct']}")
        flags = []
        if item["blocked"]:
            flags.append(f"重复拦截 {item['blocked']}")
        if item["stuck"]:
            flags.append(f"卡住提示 {item['stuck']}")
        if item["abandoned"]:
            flags.append("提前收手")
        if item["tripwires"]:
            flags.append(f"蜜罐话术 {item['tripwires']}")
        if item["breaker"]:
            flags.append("熔断")
        if item["bad_action"]:
            flags.append(f"非法输出 {item['bad_action']}")
        if flags:
            head += "  " + " / ".join(flags)
        lines.append(head)
        if item["excluded"]:
            lines.append("  已排除：" + ", ".join(item["excluded"][-6:]))
        for thought in item["thoughts"]:
            lines.append(f"  想：{thought}")
        for last in item["last"]:
            lines.append(f"  {last}")
    return "\n".join(lines)
