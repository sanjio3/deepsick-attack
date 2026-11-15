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

评测里跑的是 `bench-solve`，入口是 `solver.py`。它是四层结构，每层各管一件事，
模型只在第 3 层出现：

### 感知层（`sense.py`）

平台返回的 `container_addr` 只是线索，不是攻击面——同一宿主机 IP 上映射着多道题的
不同端口，给了 `:22` 不代表这题只有 SSH。所以开场由代码自己扫、自己抓 banner、自己
判协议，不经过模型。

- TCP connect 扫描，默认只扫**提示端口及其 ±10 邻域**。这一条是被实测逼出来的：
  扫全端口表会命中同一台上别的题的服务，把 agent 引去攻击错误容器。`deep=True`
  才升级到 200 个常用端口（模型发现该有东西的地方没东西时会主动调 `rescan`）。
- banner 抓取按原始字节判协议：SSH / HTTP / TLS / FTP / SMTP / POP3 / IMAP /
  MySQL / Redis / VNC。协议由字节决定，不由端口号猜——靶标常用 30000+ 的随机端口
  跑 HTTP。
- Web 入口选择以 fingerprint 判出的协议为准，且**提示端口优先**，不用「碰到的第
  一个 http 服务」。
- UDP 探测与 mDNS 服务发现（动态靶标靠 mDNS 公布真实端口），DNS 查询（TXT 常藏 flag）。

### 事实板（`facts.py`）

观测压成结构化事实并落 jsonl：service / route / credential / tripwire / artifact /
flag，每条带 `risk`。给模型看的是事实摘要，不是最近 8 条原文——旧实现 1800 字符一
截断，第 3 步发现的东西第 10 步就丢了。容器被杀、上下文被裁，状态都还在。

### 候选意图（`playbook.py`）

模型不再在无限动作空间里自由编 JSON，而是从代码根据事实生成的 4-8 条候选里挑一条
（`{"pick": "http:80:home"}`），必要时才自己写动作。决策面从「任意动作」缩到
「N 选 1」，这是 Flash 级模型能力范围内能做的判断。

候选生成带策略：命中 risky（疑似蜜罐/主动防御）服务的候选排到队尾；已试过的候选
直接剔除；`http:*:missing` 这条是对必然不存在的路径发请求，用「是否也返回 200」
做最便宜的蜜罐识别。

### 探测器与提交

`playbook.detect()` 只吃真实字节，模型自述不参与：是否出 flag、是否命中主动防御话术
（detected/blocked/封禁/蜜罐等）、是否「太配合」（一次请求就给 root 或私钥）。

提交策略是**疑似即提交**。强特征（`flag{...}`、`CTF{...}`、`TSEC{...}`）直接交；
弱特征（任意 `xxx{...}`）只要花括号内不是代码语法就交。唯一硬性过滤是代码片段：
括号里出现 `:` `;` `(` `)` `'` `"` `=` `/` `<` `>` 的一律丢弃——`.cls{a:b}`、
`foo{bar:2}` 属于这种，实测曾让单题出现 5 次 `answer_wrong`。

上一轮曾把闸门收到「弱特征必须有语义旁证」，结果是**整轮 0 次提交**。0 次提交拿不
到任何反馈，比交错了更糟，所以现在改成宁可交、由平台判。提交实时进行，用平台返回的
`correct` 与「已中几/共几个」当反馈。单题封顶 15 条。

模型输出空 `flags` 不会结束本题，只是被要求继续换候选。

### 工具集

标准库部分：`http_request`（保持 cookie）、`http_get`、`http_post`、`port_scan`、
`tcp_send`、`shell`、`decode`、`udp_probe`、`mdns`、`dns_query`。

`vendor/` 下的 manylinux 轮子提供 SSH 与 DNS 能力：`ssh_audit`（读版本与允许的认证
方式）、`ssh_login`（只试 4 组常见口令，不做字典爆破，登录后自动找 flag 文件）。
7 道题里有 3 道只暴露 `:22`，纯标准库打不动。缺依赖时这些工具降级返回说明，不抛异常。

打靶流量强制直连：工具集显式关闭代理，`shell` 也剥掉 `*_proxy`。环境里若有出网代理，
发往靶标的请求会被塞进代理，表现为 502 而不是靶标响应。

节奏控制：同一主机两次动作之间至少间隔 0.9 秒；同一动作连续三次触发 loop guard 强制
换路。主动防御类靶标对高频请求敏感，打得太急会被判定为扫描器。

上下文成本：每步只发「题面 + 事实摘要 + 候选 + 最近 3 步原始观测」，不累积历史消息。
单题受 `--challenge-seconds`（默认 780 秒）与 `--max-steps`（默认 40）双重约束，整轮
受 `--total-seconds`（默认 6300 秒）约束。单题取 13 分钟而不是 15 分钟，是为了给整轮
留余量：上一轮 7 道题各占满 900 秒，正好吃光 6300 秒总预算，最后一道拿到 0 秒被跳过。

## 平台托管镜像

`Dockerfile` 以 `python:3.11-slim` 为基础，入口为 `python -m deepsick_attack bench-solve`。`.dockerignore` 已排除 `.env` 与所有运行产物，凭据不会进入镜像。

第三方依赖以 **manylinux 轮子入库**（`vendor/wheels/`，7MB），构建期由 `vendor/install_vendor.py` 解包成 `vendor/site-packages/` 并加进 `PYTHONPATH`。这样零 daemon 构建与 Docker 构建产出一致，运行期不装 pip、不联网。轮子是 `manylinux2014_x86_64` + `cp311`，对应基础镜像的 ABI。重新取轮子：

python -m pip download --only-binary=:all: --platform manylinux2014_x86_64 --python-version 311 --no-deps -d vendor/wheels paramiko cryptography bcrypt pynacl cffi pycparser dnspython

bash build_image.sh

产出 `dist/deepsick-attack-image-oci.tar.gz`，对应平台「上传 Agent 镜像」要求的 `.tar.gz`。平台在创建跑分任务后注入 `BENCHMARK_TOKEN` 与 `BENCHMARK_BASE_URL`；模型侧通过环境变量 `MINIMAX_API_KEY`（托管沙箱内指向网关地址）注入。

镜像格式必须是 OCI Image Layout（`oci-layout` + `index.json` + `blobs/sha256/*`）。legacy `docker save` 的归档布局平台不认，实测报 `app_dist is not a valid OCI image archive (missing oci-layout / index.json)`。基础层直接复用镜像源里已有的 gzip blob，只把媒体类型换成 `application/vnd.oci.image.layer.v1.tar+gzip`；应用层单独压 gzip 并计算 diff_id。

没有 Docker daemon 时用离线构建器，效果等价：

python build_image_offline.py

它会先确认 vendor 依赖已解包，再按 Registry V2 协议从可访问的镜像源拉取基础层（`docker.m.daocloud.io` 等国内镜像站），按 OCI 布局组装并 gzip，`--format docker` 可退回 legacy 布局做兼容验证。构建过程自校验：`oci-layout` 与 `index.json` 齐备、index→manifest→config 引用链完整、每个层压缩后 digest 与解压后 diff_id 双重核对、Entrypoint / WorkingDir / PYTHONPATH 正确、入口文件存在且没有混入 `.env`。任一项不通过就报错退出，不产出坏镜像。

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
