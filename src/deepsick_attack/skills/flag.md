# flag 收尾纪律

适用：任何时候拿到疑似 flag 字符串。

规则：
- flag 正则：flag{...}、TSec{...}、ctf{...}，也要留意裸 hash（32/40/64 位 hex）。
- 常见藏点一次打完：
  ls -la / /root /home 2>/dev/null; cat /flag* /root/flag* /home/*/flag* 2>/dev/null; env | grep -i flag
- 页面里看到 flag 直接交；文件里读到先 cat 全文确认再交。
- flag 在「需要会话的页面」里 → 先补登录再读。
- 交卷用 submit_flag 工具（flags 数组），平台反馈 correct=false 不代表这条路错了，
  可能只是格式问题：去前后空格、大小写、转义。

停止：平台确认 correct 后继续找剩余 flag（flag_count 告诉你还有几把）。
