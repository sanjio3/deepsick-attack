"""命令行入口。

所有子命令先加载并校验配置，配置不合法直接退出，避免带病运行。
运行状态一律经 events.emit 输出，可被前端或测试接管。
凭据只从环境变量或 .env 读取，不出现在任何输出里。
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from . import __version__
from .agent import run_target, self_test
from .backends import MiniMaxLLM
from .config import ConfigError, DEFAULT_POLICY, DEFAULT_WORKSPACE, load_policy, stage_ids
from .events import emit
from .llm import LLMConfigError, LLMError, MiniMaxClient, get_config
from .bench_client import (
    BenchAPIError,
    BenchConfigError,
    BenchConnectionError,
    run_benchmark,
)
from .submission import build
from .tsecbench import BenchError, create_run, get_set, list_sets


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
    sub.add_parser("llm-check", help="验证 MiniMax key 与模型连通性")

    run = sub.add_parser("run", help="跑单个靶标")
    run.add_argument("--target", type=int, required=True)
    run.add_argument("--workspace", default=str(DEFAULT_WORKSPACE))
    run.add_argument("--max-steps", type=int, default=24)
    run.add_argument("--backend", choices=["offline", "minimax"], default="offline")
    run.add_argument("--inject-failure", default=None, metavar="STAGE",
                     help="自检用：让指定阶段的标准动作失败一次")

    check = sub.add_parser("self-test", help="离线自检，不发真实网络请求")
    check.add_argument("--workspace", default=str(DEFAULT_WORKSPACE))

    pack = sub.add_parser("pack", help="赛前生成提交 ZIP")
    pack.add_argument("--out", default=None)

    sub.add_parser("bench-sets", help="列出 TSecBench 公开题集，无需 token")
    bench_solve = sub.add_parser(
        "bench-solve", help="按平台官方协议跑一轮答题流程，需 BENCHMARK_* 环境变量")
    bench_solve.add_argument(
        "--solver", choices=["auto", "llm", "stub"], default="auto",
        help="auto: 有模型凭据用真实解题器，否则退回占位器（不提交任何 Flag）")
    bench_solve.add_argument("--max-steps", type=int, default=None,
                             help="单题最大动作步数，默认取 BENCH_MAX_STEPS 或 90")
    bench_solve.add_argument("--total-seconds", type=int, default=None,
                             help="整轮总时间预算，默认取 BENCH_TOTAL_SECONDS 或 27000（v2 窗口 8 小时）")
    bench_solve.add_argument("--challenge-seconds", type=int, default=None,
                             help="单题时间预算，默认取 BENCH_CHALLENGE_SECONDS 或 780")
    bench_solve.add_argument("--passes", type=int, default=None,
                             help="跑几轮，默认取 BENCH_RETRY_PASSES 或 2；第二轮只翻打没解出来的题")
    bench_solve.add_argument("--only", default=None, metavar="CODE",
                             help="只跑题号前缀匹配的题（本地 Agent 模式单题调试，例如 a-04）")

    bench_set = sub.add_parser("bench-set", help="查看单个题集详情，无需 token")
    bench_set.add_argument("--set", required=True, metavar="SET_ID")

    bench_run = sub.add_parser("bench-run", help="创建一次评测，需要 TSECBENCH_TOKEN")
    bench_run.add_argument("--set", required=True, metavar="SET_ID")
    bench_run.add_argument("--agent-id", default=None)
    bench_run.add_argument("--base-model", default=None)
    return parser


def _select_solver(args):
    """按 --solver 选解题器。auto 模式下缺凭据就退回占位器，绝不假装能答题。"""
    from .bench_client import stub_solver
    from .solver import make_llm_solver

    if getattr(args, "challenge_seconds", None):
        os.environ["BENCH_CHALLENGE_SECONDS"] = str(args.challenge_seconds)
    if getattr(args, "max_steps", None):
        os.environ["BENCH_MAX_STEPS"] = str(args.max_steps)
    if getattr(args, "total_seconds", None):
        os.environ["BENCH_TOTAL_SECONDS"] = str(args.total_seconds)

    if args.solver == "stub":
        emit("solver_selected", solver="stub", note="占位器不产出任何 Flag")
        return stub_solver
    if args.solver == "llm":
        return make_llm_solver(
            max_steps=args.max_steps,
            total_seconds=args.total_seconds,
            shell_timeout=int(os.environ.get("BENCH_SHELL_TIMEOUT", "30")),
        )
    # auto
    try:
        get_config()
    except LLMConfigError as exc:
        emit("solver_selected", solver="stub",
             note=f"未配置模型凭据，退回占位器（本轮不会提交 Flag）：{exc}")
        return stub_solver
    return make_llm_solver(
        max_steps=args.max_steps,
        total_seconds=args.total_seconds,
        shell_timeout=int(os.environ.get("BENCH_SHELL_TIMEOUT", "30")),
    )


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

    if args.command == "llm-check":
        try:
            config = get_config()
            reply = MiniMaxClient(config).check()
            emit("llm_ok", base_url=config["base_url"], model=config["model"],
                 effort=config["effort"], reply=reply["text"][:80],
                 stop_reason=reply["stop_reason"], usage=reply["usage"])
            return 0
        except (LLMConfigError, LLMError) as exc:
            emit("llm_error", detail=str(exc)[:300])
            return 1

    if args.command == "run":
        try:
            llm = MiniMaxLLM() if args.backend == "minimax" else None
        except (LLMConfigError, LLMError) as exc:
            emit("llm_error", detail=str(exc)[:300])
            return 1
        result = run_target(
            args.target, policy, args.workspace,
            args.max_steps, args.inject_failure, llm=llm,
        )
        emit("result", **result)
        return 0 if result["proved"] else 1

    if args.command == "self-test":
        # 自检必须从空工作区开始。Blackboard 是按目标落盘的，上一轮的
        # trace.jsonl 会让本次「恢复」到已完成的路径上，一步不执行却报
        # proved=False（反过来也可能掩盖问题）。所以这里用一次性临时目录。
        import tempfile
        with tempfile.TemporaryDirectory(prefix="deepsick-selftest-") as tmp:
            summary = self_test(policy, tmp)
        return 0 if (summary["normal"]["proved"]
                     and summary["with_failure"]["proved"]) else 1

    if args.command == "pack":
        path = build(args.out)
        emit("packed", path=str(path), bytes=path.stat().st_size)
        return 0

    if args.command == "bench-sets":
        try:
            sets = list_sets()
            emit("bench_sets", count=len(sets), sets=[
                {"id": item.get("id"), "name": item.get("name"),
                 "challenge_count": item.get("challenge_count"),
                 "flag_total": item.get("flag_total")}
                for item in sets
            ])
            return 0
        except BenchError as exc:
            emit("bench_error", detail=str(exc)[:300])
            return 1

    if args.command == "bench-set":
        try:
            detail = get_set(args.set)
            emit("bench_set", id=detail.get("id"), name=detail.get("name"),
                 challenge_count=detail.get("challenge_count"),
                 flag_total=detail.get("flag_total"),
                 max_score=detail.get("max_score"),
                 estimated_time=detail.get("estimated_time"),
                 exam_mode=detail.get("exam_mode"))
            return 0
        except BenchError as exc:
            emit("bench_error", detail=str(exc)[:300])
            return 1

    if args.command == "bench-run":
        options = {}
        if args.agent_id:
            options["agent_id"] = args.agent_id
        if args.base_model:
            options["base_model"] = args.base_model
        try:
            result = create_run(args.set, **options)
            emit("bench_run_created", run=result)
            return 0
        except BenchError as exc:
            emit("bench_error", detail=str(exc)[:300])
            return 1

    if args.command == "bench-solve":
        try:
            solver = _select_solver(args)
            summary = run_benchmark(solver=solver,
                                    total_seconds=args.total_seconds,
                                    passes=args.passes,
                                    only=args.only)
            emit("bench_done", **summary)
            return 0
        except (BenchConfigError, BenchConnectionError, BenchAPIError) as exc:
            emit("bench_error", detail=str(exc)[:300])
            return 1

    parser.print_help()
    return 0
