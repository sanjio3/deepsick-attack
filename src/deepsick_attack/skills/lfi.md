# lfi / 路径穿越 / 任意文件读取

适用：参数名像文件（file/path/download/src/include/name/page/f/id=xx.pdf），或已知 download/readfile 类路由。

打法（顺序执行，一条命令多个 payload）：
- 首试绝对路径穿越：?id=../../../../etc/passwd 与 ..%2f..%2f..%2fetc%2fpasswd 编码变体。
- 常见目标：/etc/passwd、/flag、/flag.txt、/proc/self/environ、应用配置（config.php、.env、settings.py、application.yml）、日志 /var/log/nginx/access.log。
- PHP 类站再试 php://filter/convert.base64-encode/resource=index.php 读源码；data:// 直解 RCE。
- 需要会话时先登录再打；带 cookie：curl -b "PHPSESSID=xxx"。

判定：出现 root:x:0:0 / flag{ / 文件正文 → fact(kind=file_read) + 证据落盘。
已能读文件 → 立即派生「读配置拿凭据」「读日志找 session」两条 intent。

停止：三种编码都无差异回显（长度一致）且无报错差异，标 dead 并写明。
