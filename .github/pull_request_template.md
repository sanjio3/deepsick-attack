## 改动内容

简要说明改了哪些文件、为什么改。

## 配置影响

- [ ] 未改动 `config/policy.json` 的 `official_path` 顺序
- [ ] 未改动退出判据与 `path_formula` 权重
- [ ] 若已改动，已在描述里写明赛方依据或实测结论

## 验证

- [ ] `python -m unittest discover -s tests -v` 通过
- [ ] `python run.py validate` 通过
- [ ] `python run.py self-test` 两条路径均盖章

## 安全检查

- [ ] 未包含真实靶标地址、Flag、凭据、cookie 或 token
- [ ] 未包含 `workspace/`、`evidence/`、`*.zip` 等运行产物
- [ ] 新增的敏感路径已加入 `.gitignore`

## 协作

- [ ] 已指派另一位成员 review
