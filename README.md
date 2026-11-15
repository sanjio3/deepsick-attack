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
- `src/deepsick_attack/`：正式 Python 包，含 cli、config、models、events、backends、blackboard、stage_runner、path_score、verifiers、agent、submission，以及平台侧的 bench_client、solver、llm、tsecbench。
- `tests/`：标准库 unittest 用例，零第三方依赖。
- `build_image.sh`：有 Docker daemon 时的标准构建。
- `build_image_offline.py`：无 Docker daemon 时按 Registry V2 + `docker save` 归档布局直接组装镜像，零第三方依赖。
- `SKILL.md`：赛事 Skill 入口文件。
- `.github/`：CI 工作流、CODEOWNERS 与 PR 模板。

## 配置

`official_path` 的顺序就是路径匹配度的得分口径，改顺序等于改得分规则。每个阶段必须提供 action、exit_criteria、fallbacks 与 evidence 说明。启动时会做配置校验，缺字段、重复 id、非法 detector 或正则错误都会直接失败。

真实靶标地址与本地私有配置放 `config/policy.local.json`，该文件已被 gitignore，不要提交。运行时用 `--policy` 指定。

## 测试

python -m unittest discover -s tests -v

覆盖配置校验、路径打分、退出判据、判定器、黑板状态与端到端两条执行路径。离线自检还会注入一次阶段失败，验证只在阶段内兜底、不跨阶段跳步。

## 模型配置

在项目根创建 `.env`，该文件已被 `.gitignore` 忽略，提交物白名单也不包含它。可用变量：

- `MINIMAX_API_KEY`：必填，从 MiniMax 开放平台获取。
- `MINIMAX_BASE_URL`：默认 `https://api.minimax.cn/anthropic`。
- `MINIMAX_MODEL`：默认 `MiniMax-M3.1-Flash`。
- `MINIMAX_EFFORT`：思考深度，默认 `low`，可选 `medium` / `high` / `xhigh` / `max`。
- `MINIMAX_MAX_TOKENS`：默认 4096，过小会因 thinking 占满而没有文本输出。

python run.py llm-check

python run.py run --target 1 --backend minimax

真实模型只负责把阶段动作模板展开成具体命令。若模型输出不在当前阶段允许集合内，代码会回退到官方标准动作，避免幻觉或跳步破坏路径匹配度。默认 `--backend offline`，不消耗 token。

## TSecBench 试跑

python run.py bench-sets

python run.py bench-set --set bs-6c730ae2487f

python run.py bench-run --set bs-6c730ae2487f

题集列表与详情可匿名读取；创建评测需要平台 OAuth token，通过环境变量 `TSECBENCH_TOKEN` 提供，不要写进项目文件。评测平台会记录执行轨迹与工具调用，本地补写的轨迹不能替代真实动作。

容器内实际答题由 `bench-solve` 完成，`BENCHMARK_TOKEN` 与 `BENCHMARK_BASE_URL` 由平台注入：

python -m deepsick_attack bench-solve --solver auto

`--solver auto` 在有模型凭据时使用真实解题器，缺凭据则退回占位器并明确说明本轮不提交任何 Flag。可选预算参数 `--max-steps`、`--challenge-seconds`、`--total-seconds`，也可用环境变量 `BENCH_MAX_STEPS`、`BENCH_CHALLENGE_SECONDS`、`BENCH_TOTAL_SECONDS`、`BENCH_SHELL_TIMEOUT` 覆盖。

本地验证整条链路不需要真实平台：起一个模拟 Challenges API，把 `BENCHMARK_BASE_URL` 指向它、`BENCHMARK_TOKEN` 填对应值即可跑通 list → start → 解题 → submit → close。

## 解题器

`src/deepsick_attack/solver.py` 是真实靶标执行器，沿用本项目「生成与判定分离」的硬规则：

- 模型只负责在固定工具集里挑下一个动作并给出判断理由，每轮输出一个 JSON 对象。
- 动作由代码真正执行并记录观测，观测再回灌给模型，形成闭环。
- Flag 由代码用正则从真实响应里独立提取，模型自报的 Flag 必须能在观测里找到出处才提交，找不到就拒绝。这样即使模型幻觉，也不会把编造的字符串交上去。

工具集全部基于标准库，因为 `python:3.11-slim` 里没有 nmap、curl、nc：`http_request`（带 cookie 保持）、`http_get`、`http_post`、`port_scan`、`tcp_send`（原始 TCP，用于非 HTTP 服务）、`shell`（沙箱内执行，带超时）、`decode`（base64 / hex / url / rot13）。

打靶流量强制直连：工具集显式关闭代理，`shell` 也会剥掉 `*_proxy` 环境变量。否则环境里若存在出网代理，发往靶标的请求会被塞进代理，表现为 502 而不是靶标响应。

上下文成本是受控的：每步只发「题面 + 最近 8 步观测」，不累积历史消息，避免 token 随步数平方增长撑爆窗口。单题受 `--challenge-seconds` 与 `--max-steps` 双重约束，整轮再受 `--total-seconds` 约束。

## 平台托管镜像

`Dockerfile` 以 `python:3.11-slim` 为基础，零 pip 依赖，入口为 `python -m deepsick_attack bench-solve`。`.dockerignore` 已排除 `.env` 与所有运行产物，凭据不会进入镜像。

bash build_image.sh

产出 `dist/deepsick-attack-image.tar.gz`，对应平台「上传 Agent 镜像」要求的 `.tar.gz`。平台在创建跑分任务后注入 `BENCHMARK_TOKEN` 与 `BENCHMARK_BASE_URL`；模型侧通过环境变量 `MINIMAX_API_KEY`（托管沙箱内指向网关地址）注入。

没有 Docker daemon 时用离线构建器，效果等价：

python build_image_offline.py

它按 Registry V2 协议从可访问的镜像源拉取基础层，再按 legacy `docker save` 归档布局（`manifest.json` / `<config-sha>.json` / `<layer-id>/{VERSION,json,layer.tar}` / `repositories`）组装并 gzip。构建过程自校验：每个基础层解压后的 sha256 必须等于 config 里登记的 diff_id，config 文件名必须等于其内容摘要，应用层必须包含入口且不得混入 `.env`。任一项不通过就报错退出，不产出坏镜像。

python build_image_offline.py --verify-only

只校验已有产物结构，便于在推给平台前复检。

答题流程按平台官方《Challenges API 接入文档》实现，位于 `src/deepsick_attack/bench_client.py`：header `BENCHMARK_TOKEN` 鉴权，顺序为 list → start → 解题 → submit → close，串行执行以保证活跃容器不超过 3 个；hint 接口会扣减得分，默认不调用；`duplicate` 幂等跳过；`finally` 中必定 close。官方 SDK 为 `tsec-benchmark`，本项目用标准库实现同一协议以避免镜像依赖 pip 网络。

镜像入口默认 `--solver auto`，有模型凭据就走真实解题器。仍保留 `--solver stub` 作为流程联调用的占位器，它只驱动协议、不提交任何 Flag，避免把演示字符串误交上去。

## CI 状态

GitHub Actions 工作流配置保存在 `docs/ci-workflow.yml`。当前 GitHub 令牌缺少 `workflow` scope，无法推送 `.github/workflows/` 下的文件，因此 Actions 暂未启用。补齐 scope 后把该文件移到 `.github/workflows/ci.yml` 并提交即可启用，CI 会在 Python 3.10 到 3.13 上跑同一组单测、配置校验与离线自检。

## 赛场接入

只需替换 `src/deepsick_attack/backends.py` 里的两个类：把 `LLMClient` 换成真实模型客户端，把 `Executor` 换成授权范围内的确定性工具执行器。主循环、判定器与路径验收不需要改。每一步必须产生真实工具输出，平台侧靠流量与审计日志还原路径。

## 提交物

赛前才执行 `python run.py pack`，生成 Skill ZIP。日常开发与自检不会触发打包。

## 安全边界

只对 `scope_allowlist` 内的授权靶标执行动作。Flag 必须由本轮工具输出命中，前置存在带证据的利用阶段，并用不同命令独立复现一次。反伪完成清单六条未全过不得盖章。真实地址、Flag、凭据、token、运行产物一律不入库。
