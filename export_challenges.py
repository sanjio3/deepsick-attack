#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""导出靶场全部题目清单（含官方 hint），并按漏洞族给出分工建议。

hint 是平台官方给的，直接指向漏洞类型和命中位置，是分工时最值钱的依据。
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from deepsick_attack.bench_client import ChallengesClient

# 家族归类：先按编号前缀和关键词粗分，人工可再调
FAMILY_RULES = [
    ("路径穿越/任意文件读", ("a-05", "a-09", "a-15", "d-03", "a-06")),
    ("命令注入/模板注入", ("a-09", "a-17", "a-08", "a-16")),
    ("文件上传绕过", ("a-04", "a-07", "a-08", "e3-03")),
    ("XXE/外部实体", ("a-07",)),
    ("SSRF/内网访问", ("a-16", "a-14", "d-03", "a-11")),
    ("代码执行/沙箱绕过", ("a-12", "e2-01", "e2-03", "e2-04")),
    ("反序列化", ("e2-02",)),
    ("WAF/检测绕过", ("e1-01", "e1-02", "e1-03", "e1-04", "e1-05", "e1-06",
                  "e3-01", "e3-02", "e3-04")),
    ("认证绕过/越权", ("a-03", "a-10", "a-09", "d-05", "c-01")),
    ("原型链污染", ("a-13",)),
    ("云环境", ("d-01", "d-02", "d-04", "d-06", "a-18")),
    ("固件/逆向/协议", ("f1-01", "f1-02", "f1-03", "f1-04", "f1-05",
                   "f2-01", "f2-02", "f2-03", "f2-04", "f2-05",
                   "f2-06", "f2-07", "f2-08")),
    ("综合渗透/靶链", ("b-01", "b-02", "b-03")),
    ("二进制/检测对抗", ("e3-01", "e3-02", "e3-04")),
    ("AI/模型应用", ("c-02", "c-05", "c-03", "c-08")),
    ("常规 Web/服务", ("c-01", "c-04", "c-06", "c-07", "a-01", "a-02",
                  "a-06", "a-08", "a-11", "a-13", "a-15", "a-18")),
]


def family_of(code: str) -> str:
    for name, codes in FAMILY_RULES:
        if code in codes:
            return name
    return "未归类"


def clean(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text


def main() -> None:
    client = ChallengesClient()
    items = client.list_challenges()
    print(f"共 {len(items)} 题，开始取 hint …", flush=True)

    rows = []
    for index, item in enumerate(items, 1):
        hint = ""
        try:
            hint = clean(client.get_hint(item.unique_code).hint)
        except Exception as exc:  # noqa: BLE001
            hint = f"(取 hint 失败: {type(exc).__name__})"
        rows.append({
            "code": item.unique_code,
            "difficulty": item.difficulty,
            "score": item.total_score,
            "flags": item.flag_count,
            "done": item.is_completed,
            "desc": clean(item.description),
            "hint": hint,
            "family": family_of(item.unique_code),
        })
        print(f"  [{index:2d}/{len(items)}] {item.unique_code} {hint[:40]}", flush=True)

    out_dir = os.path.dirname(os.path.abspath(__file__))
    md_path = os.path.join(out_dir, "靶场题目清单.md")
    csv_path = os.path.join(out_dir, "靶场题目清单.csv")

    done = [r for r in rows if r["done"]]
    todo = [r for r in rows if not r["done"]]

    lines = [
        "# TSecBench 靶场题目清单",
        "",
        f"生成时间：{__import__('datetime').datetime.now():%Y-%m-%d %H:%M}　"
        f"共 {len(rows)} 题，已完成 {len(done)}，待解 {len(todo)}，"
        f"总分 {sum(r['score'] for r in rows)} 分",
        "",
        "「hint」是平台官方给的提示，直接指向漏洞类型和命中位置——**先读 hint 再动手**，"
        "能省掉大量盲猜步数。",
        "",
        "## 已完成",
        "",
        "| 编号 | 难度 | 分值 | flag | 题目 | 提示 |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(done, key=lambda x: x["code"]):
        lines.append(f"| `{r['code']}` | {r['difficulty']} | {r['score']} | "
                     f"{r['flags']} | {r['desc']} | {r['hint']} |")

    lines += [
        "",
        "## 待解（按编号）",
        "",
        "| 编号 | 难度 | 分值 | flag | 题目 | 提示 |",
        "|---|---|---|---|---|---|",
    ]
    for r in sorted(todo, key=lambda x: x["code"]):
        lines.append(f"| `{r['code']}` | {r['difficulty']} | {r['score']} | "
                     f"{r['flags']} | {r['desc']} | {r['hint']} |")

    groups: dict[str, list] = {}
    for r in todo:
        groups.setdefault(r["family"], []).append(r)
    lines += ["", "## 按漏洞族分组（分工建议）", ""]
    for name in sorted(groups, key=lambda k: -len(groups[k])):
        members = groups[name]
        total = sum(m["score"] for m in members)
        lines.append(f"### {name}　{len(members)} 题 / {total} 分")
        lines.append("")
        for r in sorted(members, key=lambda x: x["code"]):
            lines.append(f"- `{r['code']}`（{r['difficulty']} {r['score']}分）"
                         f"　{r['desc']}\n  - hint：{r['hint']}")
        lines.append("")

    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as handle:
        handle.write("编号,难度,分值,flag数,状态,家族,题目,提示\n")
        for r in sorted(rows, key=lambda x: x["code"]):
            handle.write(f'"{r["code"]}","{r["difficulty"]}",{r["score"]},{r["flags"]},'
                         f'{"已完成" if r["done"] else "待解"},"{r["family"]}",'
                         f'"{r["desc"]}","{r["hint"]}"\n')

    print(f"\n已写出：\n  {md_path}\n  {csv_path}")


if __name__ == "__main__":
    main()
