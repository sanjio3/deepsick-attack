# recon 侦察

适用：开局、图空、模型连续无新事实。

打法：
- 首页/登录页必须 curl -i 看全响应头与正文，别只看状态码。
- 路径批量探测一条命令打完：
  for p in admin api login dashboard robots.txt .git/config .env backup.php flag.php upload; do echo -n "$p "; curl -s -o /dev/null -w "%{http_code} %{size_download}" -m 6 http://HOST:PORT/$p; echo; done
- 响应里的链接、表单、注释、前端 JS 里的 API 路径都要读；base64 长串先 decode 看内容。
- 非常规端口给的服务也可能是本题主战场（平台给的端口没响应时扫 -p4990-5010）。

判定：新路径/新参数/新凭据/新指纹 → 写 fact（kind=recon）→ 派生对应族 intent。

停止：bulk 探测过两轮且无新路径，转交模型打已派生的 intent。
