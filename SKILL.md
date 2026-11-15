---
name: deepsick-attack
description: 智能体安全攻防挑战赛「攻击agent渗透」赛道参赛 Skill。当需要在授权靶标上按主办方公布的标准攻击路径逐阶段执行、逐步取证并夺取 Flag 时使用。适用于要求提交完整 Agent 文件与对应 Prompt、全程无人工纠偏、且平台依据真实流量与审计日志还原攻击过程的赛制。
---

# deepsick-attack

## 何时使用

赛方公布标准攻击路径，且该路径就是最优解。此时最快到达与按顺序打卡是同一条路，不需要做开放式路径搜索，也不需要多目标权衡。正确做法是忠实复现标准路径，并为每一步留下真实、可被平台采集到的观测证据。

## 赛制与得分映射

5 个靶标，每个靶标 1 个 Flag，命中得 200 分。每靶标另有最多 40 分攻击路径匹配度，由实际轨迹与标准路径的对齐程度决定。平台侧依据真实执行轨迹、网络流量和主机审计日志还原过程，因此本地写的报告不能替代真实动作。

提交物为 Skill 文件或 ZIP，接受 .md 与 .zip。平台提交记录含 artifact、report、description 三个字段，本 Skill 的 trace.jsonl 与各靶标 evidence 目录可直接用于后两个字段。

全程无人工纠偏。审批、纠偏、复核必须在赛前写进代码与 Prompt，运行时不等待任何人工输入。

## 机制落点（artex 式）

1. 双图分工：`attack_graph.py` 资产图存入口与待验证边，`explore_graph.py`
   探索图存 intent/fact/finding 血缘；flag 与封锁都带证据。
2. 状态外置：`workspace.py` 每题工作区（notes/todolist/evidence），上下文
   压缩不丢事实；`agent_loop.py` 的 GC 把超长输出归档，正文在图与笔记里。
3. 双角色同脑：worker 认领 intent 走透、planner 读图派方向，靠注入指令切换；
   intent 收口或连续空转自动触发规划轮。
4. 按族战术卡：`src/deepsick_attack/skills/` 十一张卡，认领意图后按族加载，
   主提示词保持短小。
5. 原生工具协议：`llm.py` 走 Anthropic 兼容 tool_use/tool_result 多轮对话，
   不再让模型输出 JSON 文本再解析。

## 文件清单

- `SKILL.md`：本文件，Skill 入口。
- `config/policy.json`：主办方标准路径、退出判据、备选动作、靶标白名单、评分口径。唯一权威配置。
- `src/deepsick_attack/`：正式 Python 包，零第三方依赖；核心为 agent_loop / attack_graph / explore_graph / workspace / solver / llm 与 skills/ 战术卡。
- `prompts/planner.md`、`prompts/worker.md`、`prompts/auditor.md`：三份提交用 Prompt。
- `tests/`：标准库 unittest 用例。
- `README.md`、`CONTRIBUTING.md`：工程说明与双人协作规范。

## 运行

python -m deepsick_attack validate
python -m deepsick_attack llm-check
python -m deepsick_attack bench-solve --only a-04 --log-file logs/run.jsonl

如需命令行工具，可执行 `python -m pip install -e .` 后使用 `deepsick-attack`。
测试：`python -m unittest discover -s tests`，零第三方依赖。

单题调试用 `bench-solve --only <题号>`；`llm-check` 先验证模型连通与工具协议。

## 赛前必做

1. 把 `config/policy.json` 的 `official_path` 换成主办方公布的标准路径，顺序必须一致。
2. 把 5 个 `TARGET_x_PLACEHOLDER` 换成真实靶标地址，本地真实配置放 `config/policy.local.json`，不要提交。
3. 为每个阶段填准 `exit_criteria` 的判据 token，判据错了会导致该阶段永远走不完或误判走完。
4. 按赛方路径匹配度口径校准 `path_formula` 权重。
5. 运行 `python run.py pack` 生成提交 ZIP，按平台要求填写 artifact、report、description。

## 硬边界

只对 `scope_allowlist` 内的授权靶标执行动作。每一步必须产生真实工具输出并落 evidence 文件。Flag 必须由本轮工具输出命中，且前置存在带证据的利用阶段，并用不同命令独立复现一次。反伪完成清单六条未全过不得盖章。收到收尾信号立即停止一切命令。
