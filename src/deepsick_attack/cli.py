"""命令行入口。

所有子命令先加载并校验配置，配置不合法直接退出，避免带病运行。
运行状态一律经 events.emit 输出，可被前端或测试接管。
"""
from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .agent import run_target, self_test
from .config import ConfigError, DEFAULT_POLICY, DEFAULT_WORKSPACE, load_policy, stage_ids
from .events import emit
from .submission import build


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deepsick-attack",
        description="按主办方标准路径逐阶段取证的攻击 Agent",
    )
    parser.add_argument("--version", action="version",
                        version=f"deepsick-attack {__version__}")
    parser.add_argument("--policy", default=None,
                        help=f"配置路径，默认 {DEFAULT_POLICY}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="只校验配置，不执行任何动作")

    run = sub.add_parser("run", help="跑单个靶标")
    run.add_argument("--target", type=int, required=True)
    run.add_argument("--workspace", default=str(DEFAULT_WORKSPACE))
    run.add_argument("--max-steps", type=int, default=24)
    run.add_argument("--inject-failure", default=None, metavar="STAGE",
                     help="自检用：让指定阶段的标准动作失败一次")

    check = sub.add_parser("self-test", help="离线自检，不发真实网络请求")
    check.add_argument("--workspace", default=str(DEFAULT_WORKSPACE))

    pack = sub.add_parser("pack", help="赛前生成提交 ZIP")
    pack.add_argument("--out", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        emit("config_ok", policy=str(args.policy or DEFAULT_POLICY),
             stages=stage_ids(policy),
             targets=policy["competition"]["targets"])
        return 0

    if args.command == "run":
        result = run_target(
            args.target, policy, args.workspace,
            args.max_steps, args.inject_failure,
        )
        emit("result", **result)
        return 0 if result["proved"] else 1

    if args.command == "self-test":
        summary = self_test(policy, args.workspace)
        return 0 if (summary["normal"]["proved"]
                     and summary["with_failure"]["proved"]) else 1

    if args.command == "pack":
        path = build(args.out)
        emit("packed", path=str(path), bytes=path.stat().st_size)
        return 0

    parser.print_help()
    return 0
