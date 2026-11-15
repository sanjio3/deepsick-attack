# deepsick-attack

智能体安全攻防挑战赛攻击赛道参赛 Agent。主办方给出的标准路径就是最优解，因此不做开放式路径搜索，也不需要在速度与打卡之间做多目标权衡：把标准路径编码成可执行剧本，逐阶段执行、逐步取证、按序打卡。

## 赛制与得分

- 5 个靶标，每个靶标 1 个 Flag，命中得 200 分。
- 每靶标另有最多 40 分攻击路径匹配度，由实际轨迹与标准路径的对齐程度决定。
- 提交物为 Skill 文件或 ZIP，接受 .md 与 .zip，平台提交记录含 artifact、report、description 字段。
- 全程无人工纠偏。平台依据真实执行轨迹、网络流量和主机审计日志还原过程，本地补写的轨迹不能替代真实动作。

## 架构

主干是确定性状态机，由 `stage_runner.py` 按 `config/policy.json` 的 `official_path` 一次推进一个阶段。每个阶段绑定一个退出判据，判据未过时只在本阶段的 fallbacks 内换手段，用完即封锁上报，绝不跨阶段跳步。

四个机制各取一个：

- artex：意图-事实-发现血缘与证据门控，落在 `blackboard.py` 与 `verifiers.py`。没有 evidence 文件的观测不算数。
- Cairn：黑板三原语与局部状态空间搜索，落在 `stage_runner.py` 与 `prompts/planner.md`。搜索空间被压缩到单阶段内部。
- CAI：异构复核与全链路追踪，落在 `prompts/auditor.md`，替代人在环路审批。
- garak：probe 与 detector 配对，落在 `stage_runner.check_exit` 与 `trace.jsonl`，每步由确定性代码裁决是否走完。

`path_score.py` 只做验收：LCS 对齐算路径分，检测跳步与捷径，不再用于全局选步。

## 快速开始

零安装入口，直接可用：

python run.py validate

python run.py self-test

python run.py run --target 1

需要命令行工具时再执行 `python -m pip install -e .`，之后可用 `deepsick-attack` 或 `python -m deepsick_attack`。本机若无法联网获取构建依赖，用 `PYTHONPATH=src python -m deepsick_attack validate` 也可以。

不安装包也可以用 `python -m unittest discover -s tests -v` 直接跑测试，测试模块会自行把 src 加入路径。

## 目录结构

- `config/policy.json`：标准路径、退出判据、备选动作、靶标白名单、评分口径。唯一权威配置。
- `prompts/`：planner、worker、auditor 三份提交用 Prompt。
- `src/deepsick_attack/`：正式 Python 包，含 cli、config、models、events、backends、blackboard、stage_runner、path_score、verifiers、agent、submission。
- `tests/`：标准库 unittest 用例，零第三方依赖。
- `SKILL.md`：赛事 Skill 入口文件。
- `.github/`：CI 工作流、CODEOWNERS 与 PR 模板。

## 配置

`official_path` 的顺序就是路径匹配度的得分口径，改顺序等于改得分规则。每个阶段必须提供 action、exit_criteria、fallbacks 与 evidence 说明。启动时会做配置校验，缺字段、重复 id、非法 detector 或正则错误都会直接失败。

真实靶标地址与本地私有配置放 `config/policy.local.json`，该文件已被 gitignore，不要提交。运行时用 `--policy` 指定。

## 测试

python -m unittest discover -s tests -v

覆盖配置校验、路径打分、退出判据、判定器、黑板状态与端到端两条执行路径。离线自检还会注入一次阶段失败，验证只在阶段内兜底、不跨阶段跳步。

## CI 状态

GitHub Actions 工作流配置保存在 `docs/ci-workflow.yml`。当前 GitHub 令牌缺少 `workflow` scope，无法推送 `.github/workflows/` 下的文件，因此 Actions 暂未启用。补齐 scope 后把该文件移到 `.github/workflows/ci.yml` 并提交即可启用，CI 会在 Python 3.10 到 3.13 上跑同一组单测、配置校验与离线自检。

## 赛场接入

只需替换 `src/deepsick_attack/backends.py` 里的两个类：把 `LLMClient` 换成真实模型客户端，把 `Executor` 换成授权范围内的确定性工具执行器。主循环、判定器与路径验收不需要改。每一步必须产生真实工具输出，平台侧靠流量与审计日志还原路径。

## 提交物

赛前才执行 `python run.py pack`，生成 Skill ZIP。日常开发与自检不会触发打包。

## 安全边界

只对 `scope_allowlist` 内的授权靶标执行动作。Flag 必须由本轮工具输出命中，前置存在带证据的利用阶段，并用不同命令独立复现一次。反伪完成清单六条未全过不得盖章。真实地址、Flag、凭据、token、运行产物一律不入库。
