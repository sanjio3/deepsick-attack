# 协作规范

本项目为两人合作参赛仓库。以下规则用于避免互相覆盖、避免把赛场敏感信息带进 Git 历史。

## 分支与合并

- `main` 为受保护分支，只接受 Pull Request 合入，不直接推送。
- 功能分支用 `feat/简短描述`，修复用 `fix/简短描述`，配置调整用 `config/简短描述`。
- 每个 PR 必须由另一位成员 review 且 CI 全绿后合并，不允许自己批准自己的 PR。
- 合并前先 rebase 到最新 main，避免无意义的合并提交。

## 提交规范

- 提交信息用 `type(scope): summary`，例如 `fix(stage_runner): 修正退出判据空 token 的判定`。
- 一个提交只做一件事。配置与代码改动分开提交，便于赛场前快速回滚。
- 提交作者按各自本机 Git 配置，不要代他人提交，也不要改写已推送的提交。

## 禁止入库的内容

- 真实靶标地址、Flag 字符串、平台回执、账号密码、API Key、token、cookie。
- `config/policy.local.json` 及任何 `*.local.json`。
- `workspace/`、`run_state/`、`evidence/`、`LIVE_CRED.txt`、`*.zip`、`*.log`。
- 上述路径已写进 `.gitignore`。新增运行产物目录时同步更新该文件。

## 改动配置的额外要求

- 改 `config/policy.json` 的 `official_path` 顺序、退出判据或 `path_formula` 权重，必须在 PR 描述里写明依据（赛方文档或实测结论）。
- 这类改动必须同步更新或新增 `tests/` 用例，并跑通全量测试与离线自检。
- 不要把本地真实配置覆盖进模板文件。

## 本地验证

合并前依次执行：

python -m unittest discover -s tests -v

python run.py validate

python run.py self-test

三条全过再提 PR。工作流配置见 `docs/ci-workflow.yml`，启用后 CI 会在 Python 3.10 到 3.13 上重复同一组检查。
