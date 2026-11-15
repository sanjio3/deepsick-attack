"""一次性探针：验证 MiniMax Anthropic 兼容端点是否支持原生 tools。

跑完即删，不进仓库。验证三件事：
1. 请求带 tools 是否被接受；
2. 返回里有没有 tool_use 块；
3. 把 tool_result 发回去会不会正常续写。
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from deepsick_attack.llm import get_config  # noqa: E402

cfg = get_config()

TOOLS = [
    {
        "name": "read_notes",
        "description": "读取当前题目的工作笔记",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": [],
        },
    },
    {
        "name": "run_cmd",
        "description": "在沙箱里跑一条命令",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]

payload = {
    "model": cfg["model"],
    "max_tokens": 2048,
    "output_config": {"effort": "low"},
    "system": "你是渗透测试 agent。用工具完成请求。",
    "tools": TOOLS,
    "messages": [
        {"role": "user", "content": "请用 run_cmd 工具执行 id 命令。"}
    ],
}

req = urllib.request.Request(
    cfg["base_url"] + "/v1/messages",
    data=json.dumps(payload).encode("utf-8"),
    method="POST",
    headers={
        "Authorization": "Bearer " + cfg["api_key"],
        "Content-Type": "application/json",
    },
)
with urllib.request.urlopen(req, timeout=120) as resp:
    raw = json.loads(resp.read().decode("utf-8"))

print("stop_reason:", raw.get("stop_reason"))
print("content types:", [b.get("type") for b in raw.get("content", [])])
tool_uses = [b for b in raw.get("content", []) if b.get("type") == "tool_use"]
print("tool_use blocks:", json.dumps(tool_uses, ensure_ascii=False)[:400])

if tool_uses:
    # 第二轮：把 tool_result 发回去，验证多轮工具协议
    follow = {
        "model": cfg["model"],
        "max_tokens": 2048,
        "output_config": {"effort": "low"},
        "system": payload["system"],
        "tools": TOOLS,
        "messages": [
            {"role": "user", "content": "请用 run_cmd 工具执行 id 命令。"},
            {"role": "assistant", "content": raw["content"]},
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_uses[0]["id"],
                        "content": "uid=0(root) gid=0(root) groups=0(root)",
                    }
                ],
            },
        ],
    }
    req2 = urllib.request.Request(
        cfg["base_url"] + "/v1/messages",
        data=json.dumps(follow).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": "Bearer " + cfg["api_key"],
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req2, timeout=120) as resp:
        raw2 = json.loads(resp.read().decode("utf-8"))
    print("=== round2 ===")
    print("stop_reason:", raw2.get("stop_reason"))
    print("content types:", [b.get("type") for b in raw2.get("content", [])])
    texts = [b.get("text", "") for b in raw2.get("content", [])
             if b.get("type") == "text"]
    print("text:", " ".join(texts)[:300])
    print("usage:", json.dumps(raw2.get("usage", {})))
