"""MiniMax Anthropic 兼容客户端，零第三方依赖。

凭据只从环境变量或项目根 .env 读取，绝不写入代码或提交到仓库。
官方文档：https://platform.minimax.cn/docs/api-reference/text-anthropic-api

关键约束：
- base_url 为 https://api.minimax.cn/anthropic ，messages 端点为 /v1/messages
- 鉴权用 Authorization: Bearer
- MiniMax-M3.1-Flash 强制开启 thinking，max_tokens 过小会导致没有文本输出
- output_config.effort 控制思考深度，low 最省 token
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_URL = "https://api.minimax.cn/anthropic"
DEFAULT_MODEL = "MiniMax-M3.1-Flash"


class LLMConfigError(Exception):
    """缺少凭据或配置不合法。"""


class LLMError(Exception):
    """请求失败，消息中不包含凭据内容。"""


def load_dotenv(path: str | Path | None = None) -> dict[str, str]:
    """把 .env 读入环境变量，已有环境变量优先，不覆盖。"""
    target = Path(path) if path else PROJECT_ROOT / ".env"
    values: dict[str, str] = {}
    if not target.exists():
        return values
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        values[key] = value
        os.environ.setdefault(key, value)
    return values


def get_config() -> dict[str, Any]:
    load_dotenv()
    api_key = (os.environ.get("MINIMAX_API_KEY")
               or os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if not api_key:
        raise LLMConfigError(
            "缺少 MINIMAX_API_KEY：请在项目根 .env 配置，该文件已被 .gitignore 忽略"
        )
    try:
        max_tokens = int(os.environ.get("MINIMAX_MAX_TOKENS", "4096"))
    except ValueError as exc:
        raise LLMConfigError("MINIMAX_MAX_TOKENS 必须是整数") from exc
    return {
        "api_key": api_key,
        "base_url": (os.environ.get("MINIMAX_BASE_URL")
                     or os.environ.get("ANTHROPIC_BASE_URL")
                     or DEFAULT_BASE_URL).rstrip("/"),
        "model": os.environ.get("MINIMAX_MODEL") or DEFAULT_MODEL,
        "effort": os.environ.get("MINIMAX_EFFORT") or "low",
        "max_tokens": max_tokens,
    }


class MiniMaxClient:
    def __init__(self, config: dict[str, Any] | None = None, timeout: int = 120):
        self.config = config or get_config()
        self.timeout = timeout

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.config["base_url"] + "/v1/messages",
            data=body,
            method="POST",
            headers={
                "Authorization": "Bearer " + self.config["api_key"],
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise LLMError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(f"网络请求失败：{type(exc).__name__}") from exc

    @staticmethod
    def _base_payload(model_key: str = "model") -> dict[str, Any]:
        return {"model": model_key}

    def complete(self, system: str, user: str = "",
                 max_tokens: int | None = None,
                 effort: str | None = None,
                 messages: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """单轮或多轮补全。给出 messages 时忽略 user，用于多步工具调用的上下文累积。"""
        raw = self.chat(system, messages or [{"role": "user", "content": user}],
                        max_tokens=max_tokens, effort=effort)
        texts = [
            block.get("text", "")
            for block in raw.get("content", [])
            if block.get("type") == "text"
        ]
        return {
            "text": "\n".join(texts).strip(),
            "stop_reason": raw.get("stop_reason"),
            "usage": raw.get("usage", {}),
            "model": raw.get("model"),
        }

    def chat(self, system: str, messages: list[dict[str, Any]],
             tools: list[dict[str, Any]] | None = None,
             max_tokens: int | None = None,
             effort: str | None = None) -> dict[str, Any]:
        """原生协议调用：返回完整响应（content 里可能有 text/tool_use 块）。

        这是 agent 循环的底层接口。tools 是 Anthropic 工具 schema 列表；
        tool_use 块由调用方执行后以 tool_result 塞回 messages 再调下一轮。
        实测（tools_probe_tools_api.py）MiniMax 兼容端点支持完整工具协议，
        并返回 cache_read_input_tokens（system 稳定时命中缓存）。
        """
        payload: dict[str, Any] = {
            "model": self.config["model"],
            "max_tokens": max_tokens or self.config["max_tokens"],
            "output_config": {"effort": effort or self.config["effort"]},
            "system": system,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools
        return self._post(payload)

    def check(self) -> dict[str, Any]:
        """最小连通性验证：低思考深度、短回复，不打印凭据。"""
        return self.complete(
            system="You are a concise assistant. Reply with exactly one word: OK",
            user="connectivity check",
            max_tokens=1024,
            effort="low",
        )
