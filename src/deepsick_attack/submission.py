"""赛事提交物打包。

提交形态是 Skill 文件 / ZIP，入口 SKILL.md。显式白名单打包，
workspace、__pycache__、dist、本地配置一律不进包。

赛前才执行，日常开发与自检不会触发。
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from .config import PROJECT_ROOT

INCLUDE = [
    "SKILL.md",
    "README.md",
    "CONTRIBUTING.md",
    "pyproject.toml",
    "run.py",
    "config/policy.json",
    "prompts/planner.md",
    "prompts/worker.md",
    "prompts/auditor.md",
    "src/deepsick_attack/__init__.py",
    "src/deepsick_attack/__main__.py",
    "src/deepsick_attack/agent.py",
    "src/deepsick_attack/backends.py",
    "src/deepsick_attack/blackboard.py",
    "src/deepsick_attack/cli.py",
    "src/deepsick_attack/config.py",
    "src/deepsick_attack/events.py",
    "src/deepsick_attack/models.py",
    "src/deepsick_attack/path_score.py",
    "src/deepsick_attack/stage_runner.py",
    "src/deepsick_attack/submission.py",
    "src/deepsick_attack/verifiers.py",
]

DEFAULT_OUT = PROJECT_ROOT / "dist" / "deepsick-attack-skill.zip"


def build(out: str | Path | None = None) -> Path:
    target = Path(out) if out else DEFAULT_OUT
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for rel in INCLUDE:
            source = PROJECT_ROOT / rel
            if not source.exists():
                raise FileNotFoundError(f"缺少提交物：{rel}")
            archive.write(source, arcname=f"deepsick-attack/{rel}")
    return target
