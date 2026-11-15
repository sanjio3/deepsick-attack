"""配置加载与校验。

policy.json 是赛制口径的唯一权威来源。把它当代码输入而不是随意文本：
启动即校验，配置错了要立刻失败，不能等到赛场上某个阶段永远走不完才发现。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
PROMPT_DIR = PROJECT_ROOT / "prompts"
DEFAULT_POLICY = CONFIG_DIR / "policy.json"
DEFAULT_WORKSPACE = PROJECT_ROOT / "workspace"

SUPPORTED_DETECTORS = {"contains_any", "flag"}


class ConfigError(Exception):
    """配置缺失、格式错误或语义不合法。"""


def load_policy(path: str | Path | None = None) -> dict:
    target = Path(path) if path else DEFAULT_POLICY
    if not target.exists():
        raise ConfigError(f"找不到配置文件：{target}")
    try:
        policy = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON：{target} ({exc})") from exc
    errors = validate_policy(policy)
    if errors:
        raise ConfigError("配置校验失败：\n- " + "\n- ".join(errors))
    return policy


def validate_policy(policy: Any) -> list[str]:
    """返回错误列表，空列表表示配置可用。"""
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy 顶层必须是对象"]

    competition = policy.get("competition")
    if not isinstance(competition, dict):
        errors.append("缺少 competition 对象")
    else:
        for key in ("targets", "flag_points", "path_points_per_target"):
            if key not in competition:
                errors.append(f"competition 缺少 {key}")
        targets = competition.get("targets")
        if isinstance(targets, int) and targets <= 0:
            errors.append("competition.targets 必须为正整数")

    scope = policy.get("scope_allowlist")
    if not isinstance(scope, list) or not scope:
        errors.append("scope_allowlist 必须是非空数组")
    elif isinstance(competition, dict) and isinstance(competition.get("targets"), int):
        if len(scope) != competition["targets"]:
            errors.append("scope_allowlist 数量与 competition.targets 不一致")

    regex = policy.get("flag_regex")
    if not isinstance(regex, str) or not regex:
        errors.append("缺少 flag_regex")
    else:
        try:
            re.compile(regex)
        except re.error as exc:
            errors.append(f"flag_regex 无法编译：{exc}")

    path = policy.get("official_path")
    if not isinstance(path, list) or not path:
        errors.append("official_path 必须是非空数组")
    else:
        seen: set[str] = set()
        for idx, stage in enumerate(path):
            label = f"official_path[{idx}]"
            if not isinstance(stage, dict):
                errors.append(f"{label} 必须是对象")
                continue
            sid = stage.get("id")
            if not isinstance(sid, str) or not sid:
                errors.append(f"{label} 缺少 id")
            elif sid in seen:
                errors.append(f"{label} 的 id 重复：{sid}")
            else:
                seen.add(sid)
            for key in ("label", "technique", "action"):
                if not isinstance(stage.get(key), str) or not stage[key]:
                    errors.append(f"{label} 缺少 {key}")
            criteria = stage.get("exit_criteria")
            if not isinstance(criteria, dict):
                errors.append(f"{label} 缺少 exit_criteria")
            else:
                detector = criteria.get("detector")
                if detector not in SUPPORTED_DETECTORS:
                    errors.append(
                        f"{label}.detector 必须是 {sorted(SUPPORTED_DETECTORS)} 之一，实际为 {detector}"
                    )
                tokens = criteria.get("tokens")
                if detector == "contains_any" and (
                    not isinstance(tokens, list) or not tokens
                ):
                    errors.append(f"{label}.tokens 必须是非空数组")
            if not isinstance(stage.get("fallbacks"), list):
                errors.append(f"{label}.fallbacks 必须是数组")

    formula = policy.get("path_formula")
    if not isinstance(formula, dict):
        errors.append("缺少 path_formula 对象")
    else:
        for key in ("coverage_weight", "order_weight", "skip_penalty"):
            if not isinstance(formula.get(key), (int, float)):
                errors.append(f"path_formula 缺少数值型 {key}")

    return errors


def stage_ids(policy: dict) -> list[str]:
    return [stage["id"] for stage in policy["official_path"]]


def technique_map(policy: dict) -> dict[str, str]:
    return {stage["id"]: stage["technique"] for stage in policy["official_path"]}
