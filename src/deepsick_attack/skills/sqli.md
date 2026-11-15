# sqli 注入

适用：带参数的查询接口（id/name/search/q/sort），报错回显，或搜索/列表页。

打法：
- 单引号探针：' 与 ' --  与 ' OR '1'='1，对比响应长度/报错差异。
- UNION 数列：ORDER BY 1..N 逐级或 ' UNION SELECT NULL,NULL,...-- 一次一条。
- 有回显直接 UNION 拖库：sqlite_master / information_schema.tables → 表名 → 数据 → flag。
- 无回显看时间盲注：' AND SLEEP(3)-- 响应时长变化；布尔盲注对比长度。
- 登录框优先试 ' OR '1'='1' -- 绕过。

判定：报错含 SQL 语法 / 数据拖出 / 时长显著变化 → fact(kind=injectable)。
拖出凭据 → fact(kind=creds) + 派生 auth intent。

停止：引号被转义且数字型无差异、时间盲注无延迟，标 dead。
