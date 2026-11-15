"""TSecBench Challenges API 客户端，按平台官方《Challenges API 接入文档》实现。

协议要点（均来自官方文档，不作猜测）：
- 所有 /openapi/v1/challenges/* 接口用请求头 BENCHMARK_TOKEN 鉴权。
- 顺序：list → start →（解题）→ submit → close。
- 同一时间最多启动 3 道题；本实现串行，天然满足。
- hint 会按比例扣减该题得分，默认不调用。
- 完成答题后无论成败都要 close 释放容器。
- 错误响应统一为 {"code": ..., "message": ..., "detail": {}}。

凭证只从 BENCHMARK_TOKEN / BENCHMARK_BASE_URL 环境变量读取，不写入代码或镜像。
官方 SDK 为 tsec-benchmark；本模块用标准库实现同一协议，避免镜像依赖 pip 网络。
"""
from __future__ import annotations

import inspect
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .events import emit

PATH_LIST = "/openapi/v1/challenges"
PATH_START = "/openapi/v1/challenges/start"
PATH_HINT = "/openapi/v1/challenges/hint"
PATH_SUBMIT = "/openapi/v1/challenges/submit"
PATH_CLOSE = "/openapi/v1/challenges/close"


class BenchConfigError(Exception):
    """缺少平台下发的环境变量。"""


class BenchConnectionError(Exception):
    """传输层失败。"""


class BenchAPIError(Exception):
    def __init__(self, code: str, message: str, detail: Any, status_code: int | None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.detail = detail
        self.status_code = status_code


class TaskNotFound(BenchAPIError):
    pass


class ChallengeNotFound(BenchAPIError):
    pass


class InvalidState(BenchAPIError):
    pass


class DuplicateSubmit(BenchAPIError):
    pass


class ResourceUnavailable(BenchAPIError):
    pass


class InternalError(BenchAPIError):
    pass


class ValidationError(BenchAPIError):
    pass


ERROR_MAP = {
    "task_not_found": TaskNotFound,
    "challenge_not_found": ChallengeNotFound,
    "invalid_state": InvalidState,
    "duplicate": DuplicateSubmit,
    "resource_unavailable": ResourceUnavailable,
    "internal_error": InternalError,
}


@dataclass(frozen=True)
class Challenge:
    unique_code: str
    description: str
    difficulty: str
    level: int
    total_score: int
    flag_count: int
    correct_flag_count: int
    is_completed: bool
    container_status: str
    container_addr: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> "Challenge":
        return cls(
            unique_code=str(data.get("unique_code", "")),
            description=str(data.get("description") or ""),
            difficulty=str(data.get("difficulty") or ""),
            level=int(data.get("level") or 0),
            total_score=int(data.get("total_score") or 0),
            flag_count=int(data.get("flag_count") or 0),
            correct_flag_count=int(data.get("correct_flag_count") or 0),
            is_completed=bool(data.get("is_completed", False)),
            container_status=str(data.get("container_status") or "stopped"),
            container_addr=list(data.get("container_addr") or []),
        )


@dataclass(frozen=True)
class StartResult:
    unique_code: str
    container_addr: list[str]


@dataclass(frozen=True)
class HintResult:
    unique_code: str
    hint: str | None


@dataclass(frozen=True)
class SubmitResult:
    correct: bool
    awarded: int
    cumulative_score: int = 0
    correct_flag_count: int = 0
    total_flag_count: int = 0
    matched_flag_index: int | None = None


@dataclass(frozen=True)
class CloseResult:
    unique_code: str
    closed: bool


class ChallengesClient:
    def __init__(self, base_url: str | None = None, token: str | None = None,
                 timeout: int = 30):
        self.base_url = (base_url or os.environ.get("BENCHMARK_BASE_URL", "")).strip().rstrip("/")
        self.token = (token or os.environ.get("BENCHMARK_TOKEN", "")).strip()
        self.timeout = timeout
        if not self.base_url or not self.token:
            raise BenchConfigError(
                "缺少 BENCHMARK_BASE_URL 或 BENCHMARK_TOKEN："
                "这两项在平台创建跑分任务后自动注入容器"
            )

    def _request(self, method: str, path: str, params: dict | None = None,
                 body: dict | None = None) -> Any:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"BENCHMARK_TOKEN": self.token, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            if exc.code == 422:
                raise ValidationError("validation_error", text[:300],
                                      payload.get("detail", {}), exc.code) from exc
            code = str(payload.get("code") or "http_error")
            error_cls = ERROR_MAP.get(code, BenchAPIError)
            raise error_cls(code, str(payload.get("message") or text[:300]),
                            payload.get("detail", {}), exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BenchConnectionError(
                f"请求 {method} {path} 失败：{type(exc).__name__}"
            ) from exc

    def list_challenges(self) -> list[Challenge]:
        data = self._request("GET", PATH_LIST)
        rows = data if isinstance(data, list) else data.get("items", [])
        return [Challenge.from_dict(row) for row in rows if isinstance(row, dict)]

    def start_challenge(self, unique_code: str) -> StartResult:
        data = self._request("POST", PATH_START, params={"unique_code": unique_code})
        return StartResult(str(data.get("unique_code", unique_code)),
                           list(data.get("container_addr") or []))

    def get_hint(self, unique_code: str) -> HintResult:
        data = self._request("GET", PATH_HINT, params={"unique_code": unique_code})
        return HintResult(str(data.get("unique_code", unique_code)), data.get("hint"))

    def submit_flag(self, unique_code: str, flag: str) -> SubmitResult:
        data = self._request("POST", PATH_SUBMIT,
                             body={"unique_code": unique_code, "flag": flag})
        return SubmitResult(
            correct=bool(data.get("correct", False)),
            awarded=int(data.get("awarded") or 0),
            cumulative_score=int(data.get("cumulative_score") or 0),
            correct_flag_count=int(data.get("correct_flag_count") or 0),
            total_flag_count=int(data.get("total_flag_count") or 0),
            matched_flag_index=data.get("matched_flag_index"),
        )

    def close_challenge(self, unique_code: str) -> CloseResult:
        data = self._request("POST", PATH_CLOSE, params={"unique_code": unique_code})
        return CloseResult(str(data.get("unique_code", unique_code)),
                           bool(data.get("closed", False)))


def stub_solver(challenge: Challenge, started: StartResult) -> list[str]:
    """占位解题器：明确不产出 Flag，避免把本地演示字符串误提交到平台。"""
    emit("bench_solver_stub", unique_code=challenge.unique_code,
         container_addr=started.container_addr,
         note="真实靶标执行器尚未接入，本轮不提交任何 Flag")
    return []


def _accepts_submit(fn) -> bool:
    """解题器是否接受 submit 回调。有就实时提交，拿平台反馈当信号。"""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    if "submit" in params:
        return True
    return any(p.kind == p.VAR_KEYWORD for p in params.values())


def run_benchmark(solver: Callable[[Challenge, StartResult], list[str]] | None = None,
                  client: ChallengesClient | None = None) -> dict:
    """按官方顺序驱动一轮评测，串行处理题目，保证最多 1 个活跃容器。"""
    client = client or ChallengesClient()
    solver = solver or stub_solver
    challenges = client.list_challenges()
    emit("bench_challenges", count=len(challenges),
         codes=[ch.unique_code for ch in challenges])

    summary = {"challenges": len(challenges), "started": 0,
               "submitted": 0, "correct": 0, "awarded": 0, "closed": 0}
    for challenge in challenges:
        if challenge.is_completed:
            emit("bench_skip", unique_code=challenge.unique_code,
                 reason="已完成，按官方文档跳过")
            continue
        started = client.start_challenge(challenge.unique_code)
        summary["started"] += 1
        emit("bench_started", unique_code=challenge.unique_code,
             container_addr=started.container_addr)

        def submit_one(flag: str, code: str = challenge.unique_code):
            """提交一条候选并把结果计入汇总。重复提交按幂等跳过。"""
            try:
                result = client.submit_flag(code, flag)
            except DuplicateSubmit:
                emit("bench_duplicate", unique_code=code, note="幂等跳过")
                return SubmitResult(correct=False, awarded=0,
                                    correct_flag_count=0, total_flag_count=0)
            summary["submitted"] += 1
            if result.correct:
                summary["correct"] += 1
                summary["awarded"] += result.awarded
            emit("bench_submit", unique_code=code, correct=result.correct,
                 awarded=result.awarded,
                 progress=f"{result.correct_flag_count}/{result.total_flag_count}")
            return result

        live = _accepts_submit(solver)
        try:
            if live:
                # 解题器自己提交，用平台反馈决定是否继续挖
                solver(challenge, started, submit=submit_one)
            else:
                for flag in list(solver(challenge, started) or []):
                    submit_one(flag)
        finally:
            closed = client.close_challenge(challenge.unique_code)
            summary["closed"] += 1
            emit("bench_closed", unique_code=challenge.unique_code,
                 closed=closed.closed)
    emit("bench_summary", **summary)
    return summary
