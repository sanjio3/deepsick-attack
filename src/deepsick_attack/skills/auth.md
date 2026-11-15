# auth 认证绕过 / 弱口令 / 会话

适用：登录页、302 全跳登录、admin 页需要会话、发现凭据后。

打法：
- 先试已 harvest 的凭据（图里有 creds 直接用）。
- 弱口令一条命令打完：
  for p in admin:admin root:root admin:123456 admin:password test:test vagrant:vagrant; do u=${p%%:*}; w=${p##*:}; echo -n "$u:$w "; curl -s -o /dev/null -w "%{http_code}" -m 6 -d "username=$u&password=$w" http://HOST:PORT/login.php; echo; done
- Set-Cookie 出现 PHPSESSID/session 即视为登录成功（配合 -c cookie.txt 保存）。
- 绕过路数：注册后越权访问 admin、JWT none/弱密钥、cookie 可伪造（flask session 明文）、路径大小写 /Admin、加 X-Forwarded-For: 127.0.0.1、/logout 边角未鉴权。

判定：拿到会话 → fact(kind=session) + cookie 值入 fact；graph 里因 auth 封锁的 intent 会被自动重开。
登录页恒 5xx、业务路由全 302 到它 → 登录功能本身坏了，别再猜密码，改打绕过。

停止：凭据表全试过且无 cookie，改派其它族。
