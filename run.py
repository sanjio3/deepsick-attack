#!/usr/bin/env python3
"""零安装启动器。

本机若无法 `pip install -e .`（例如离线或缺构建依赖），用这个入口即可：
    python run.py validate
    python run.py llm-check
    python run.py bench-solve --only a-04 --log-file logs/run.jsonl
    python run.py pack --out dist/skill.zip
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from deepsick_attack.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
