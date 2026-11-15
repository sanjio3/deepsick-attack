"""TSecBench 平台适配层，零第三方依赖。

公开部分：题集列表与详情可匿名读取。
受保护部分：创建评测 run 需要平台 OAuth token，从环境变量
TSECBENCH_TOKEN 读取，绝不写入代码或提交到仓库。

平台前端使用的 run 生命周期：POST /runs 创建 → GET /runs/{id}/status 轮询
→ POST /runs/{id}/finish → GET /runs/{id}/result。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

BASE_URL = "https://tsecbench.zc.tencent.com/api/v1"


class BenchError(Exception):
    """平台请求失败，错误消息中不含凭据。"""


def _request(method: str, path: str, payload=None,
             token: str | None = None, timeout: int = 30) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        BASE_URL + path, data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise BenchError(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BenchError(f"网络请求失败：{type(exc).__name__}") from exc


def token_from_env() -> str:
    return (os.environ.get("TSECBENCH_TOKEN") or "").strip()


def list_sets() -> list[dict]:
    result = _request("GET", "/benchmark-sets")
    return result if isinstance(result, list) else result.get("items", [])


def get_set(set_id: str) -> dict:
    return _request("GET", f"/benchmark-sets/{set_id}")


def create_run(set_id: str, token: str | None = None, **options) -> dict:
    token = token or token_from_env()
    if not token:
        raise BenchError(
            "缺少 TSECBENCH_TOKEN：请先登录 TSecBench 获取 token，"
            "并用环境变量提供，不要写入项目文件"
        )
    payload = {
        "set_id": set_id,
        "run_source": "local",
        "evaluation_type": "agent",
        **options,
    }
    return _request("POST", "/runs", payload, token=token)


def run_status(run_id: str, token: str | None = None) -> dict:
    return _request("GET", f"/runs/{run_id}/status", token=token or token_from_env())


def finish_run(run_id: str, token: str | None = None) -> dict:
    return _request("POST", f"/runs/{run_id}/finish", {}, token=token or token_from_env())


def run_result(run_id: str, token: str | None = None) -> dict:
    return _request("GET", f"/runs/{run_id}/result", token=token or token_from_env())
