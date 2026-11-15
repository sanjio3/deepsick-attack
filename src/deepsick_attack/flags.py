"""Flag 提取与提交策略。

上一轮我把闸门收紧到「弱特征必须有语义旁证」，结果整轮 0 次提交——比提交错
还糟，因为 0 次提交拿不到任何反馈，平台也就无法告诉你「对/不对/已中几个」。

现在的策略是「可疑即提交」，只用一条硬规则挡掉代码片段：
花括号里出现 `:` `;` `(` `)` `'` `"` `=` `/` `<` `>` 的，一律视为 JS/CSS/JSON
片段丢弃（`.cls{a:b}`、`foo{bar:2}` 都属于这种），其余候选交给平台判定。
"""
from __future__ import annotations

import re

STRONG_FLAG_PATTERNS = [
    re.compile(r"(?i)\b(?:flag|ctf|tsec|tsb|tflag|hack|pwn)\{[^}\n\r]{1,200}\}"),
    re.compile(r"(?i)\bflag[-_][A-Za-z0-9]{6,64}\b"),
]

WEAK_FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,32}\{[^}\n\r]{1,200}\}")

FLAG_CONTEXT_HINTS = (
    "flag", "secret", "answer", "correct", "congrat", "success", "you win",
    "well done", "答案是", "恭喜", "正确", "提交", "这是你的", "拿到",
)

# 花括号内出现这些字符，几乎一定是代码而不是 flag
CODE_CHARS = set(':=;()"\'/<>+,|&')

FLAG_PATTERNS = STRONG_FLAG_PATTERNS + [WEAK_FLAG_PATTERN]


def _looks_like_code(value: str) -> bool:
    inner = value[value.find("{") + 1:value.rfind("}")] if "{" in value else ""
    return any(ch in CODE_CHARS for ch in inner)


def _context_hint(body: str, start: int, end: int, window: int = 200) -> str | None:
    around = body[max(0, start - window):min(len(body), end + window)].lower()
    for hint in FLAG_CONTEXT_HINTS:
        if hint in around:
            return hint
    return None


def extract_flags(text: str, strict: bool = False) -> list[str]:
    """提取候选 Flag。去重、保持首次出现顺序。

    strict=True 时只返回强特征，用于「刚看到响应、还没核验」的场合。
    """
    body = text if isinstance(text, str) else str(text or "")
    if not body:
        return []
    found: list[str] = []
    seen: set[str] = set()

    for pattern in STRONG_FLAG_PATTERNS:
        for match in pattern.finditer(body):
            value = match.group(0).strip()
            key = value.lower()
            if len(value) < 6 or key in seen or _looks_like_code(value):
                continue
            seen.add(key)
            found.append(value)

    if strict:
        return found

    for match in WEAK_FLAG_PATTERN.finditer(body):
        value = match.group(0).strip()
        key = value.lower()
        if len(value) < 6 or key in seen or _looks_like_code(value):
            continue
        # 弱特征放行条件放宽：有语义旁证，或者本身够长（≥12）不像噪声
        if _context_hint(body, match.start(), match.end()) or len(value) >= 12:
            seen.add(key)
            found.append(value)
    return found
