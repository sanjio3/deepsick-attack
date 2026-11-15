"""artex 式 agent 循环：模型在一条持续对话里用原生工具自主解题。

这一版把决策权还给模型（这正是此前失败的根因——旧实现把模型降级成
「每步从候选里挑一个」的一次性分类器，图在它背后跑、它看不见也改不了）。

对照 artex 落进来的机制：
- 状态外置：notes.md / todolist.md / 探索图全部落盘（workspace.py +
  explore_graph.py），对话只是注意力；上下文 GC 不丢事实。
- 双角色同脑：worker 纪律（认领一条 intent、走透、写回、收口）与 planner
  纪律（读图态势、更新 todolist、派生新 intent）靠注入不同指令切换。
- 证据门控：fact/finding 必须带 evidence 文件；flag 交卷记录出处。
- 血缘链：intent 产出 fact，fact 派生新 intent，封锁方向重开要写新机理。
- 确定性快路径保留但交给模型调用：graph(op=auto_probe) 返回资产图上
  优先级最高的一条预渲染命令（a-05 三步拿 flag 靠它），用不用模型定。

工具面收成 6 个（DeepAgents/hiro 的做法，多路复用降认知负担）：
  shell / session / file / graph / submit_flag / finish
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from . import graph_exec
from .attack_graph import extract_entries
from .events import emit
from .explore_graph import ExploreGraph
from .flags import extract_flags
from .workspace import Workspace

MAX_TURNS_HARD = 200
# 单个 tool_result 在对话里保留的上限；超了就归档（正文在图/笔记/证据里）
RESULT_KEEP = 900
# 最近 N 条消息不归档
GC_KEEP_TAIL = 8
# 连续多少个「无新事实/新入口」的轮次后注入 planner 指令
STALE_PLANNER = 3
LLM_RETRIES = 3

PLANNER_NUDGE = (
    "[planner 指令] 现在切换到规划角色：\n"
    "1. graph(op=overview) 读态势（资产图 + 探索图 + 事实）。\n"
    "2. file(op=read, path=todolist.md) 读当前规划，按依赖推进：前置已成"
    "事实的下一步立刻 graph(op=add_intent) 派出去；已成完的标进完成。\n"
    "3. 事实里能派生的新方向（能读文件→读配置拿凭据；有凭据→登录；有注入→"
    "拖库）逐条派 intent，每条写清 [family] target 和 why。\n"
    "4. 没有新方向时才允许直接打：shell 跑具体命令继续探索。\n"
    "规划完回到 worker 角色继续执行。"
)

WORKER_NUDGE = (
    "[worker 指令] 继续执行：graph(op=overview) 看待验证 intent，挑一条"
    "（或 graph(op=auto_probe) 取资产图上的预渲染快打命令），用 shell 打透。"
    "完成后必须收口：graph(op=close_intent, intent_id=N, status=done|dead|"
    "blocked, verdict=...)；dead 要写清依据，拿到的结果 graph(op=add_fact) "
    "写回（kind + 一句话内容），重要响应用 file(op=append) 记进 notes.md。"
)

CONTINUE_NUDGE = (
    "[系统] 你停下来了但题目还没结束：还有 flag 没找到、intent 没收口。"
    "继续：认领/执行 intent，或者交卷 submit_flag。不要输出纯文本，"
    "用工具干活。"
)

TOOLS: list[dict[str, Any]] = [
    {"name": "shell", "description": "在沙箱里跑一条 shell 命令（20 秒上限）。同类探测必须在一条命令里用 for 循环打完，不要一条命令一个点。",
     "input_schema": {"type": "object", "properties": {
         "command": {"type": "string", "description": "完整命令行"}},
         "required": ["command"]}},
    {"name": "session", "description": "交互会话（ssh / nc / python -i / redis-cli 这类需要交互的）。op=start 发起，op=send 发送文本，op=read 读取输出，op=kill 结束。",
     "input_schema": {"type": "object", "properties": {
         "op": {"type": "string", "enum": ["start", "send", "read", "kill", "list"]},
         "id": {"type": "integer"}, "cmd": {"type": "string"},
         "text": {"type": "string"}, "wait": {"type": "number"}},
         "required": ["op"]}},
    {"name": "file", "description": "读写工作区文件（/tmp/ws/<题号>/）。op=append 追加笔记（notes.md 专用，记关键观察/结论）；op=read 读文件；op=write 写新文件或 todolist.md（规划待办整读整写）。探针脚本、webshell 源码先 write_file 落盘再执行。",
     "input_schema": {"type": "object", "properties": {
         "op": {"type": "string", "enum": ["read", "write", "append"]},
         "path": {"type": "string", "description": "相对工作区的路径，如 notes.md / todolist.md / evidence/x.txt / shell.php"},
         "content": {"type": "string"}},
         "required": ["op", "path"]}},
    {"name": "graph", "description": "攻击图操作。op=overview 读全部态势（资产+intent+fact，planner 每次 planning 前必读）；op=add_intent 派新假设（family/target/why）；op=close_intent 收口（intent_id/status/verdict，dead 必须写依据）；op=add_fact 写事实（kind/content，例如 file_read/creds/session/rce）；op=add_entry 补资产（url 或 host:port）；op=auto_probe 取资产图上优先级最高的预渲染命令（确定性快路径，拿到直接 shell 执行）；op=skill 读某族战术卡（lfi/sqli/auth/upload/cmdi/ssti/ssrf/deser/port/flag/recon）。",
     "input_schema": {"type": "object", "properties": {
         "op": {"type": "string", "enum": ["overview", "add_intent", "close_intent",
                                           "add_fact", "add_entry", "auto_probe", "skill"]},
         "family": {"type": "string"}, "target": {"type": "string"},
         "why": {"type": "string"}, "intent_id": {"type": "integer"},
         "status": {"type": "string", "enum": ["done", "dead", "blocked", "pending"]},
         "verdict": {"type": "string"}, "kind": {"type": "string"},
         "content": {"type": "string"}, "url": {"type": "string"},
         "skill": {"type": "string"}},
         "required": ["op"]}},
    {"name": "submit_flag", "description": "交卷。拿到疑似 flag 立刻提交（不要等攒齐），平台会反馈 correct 与进度。",
     "input_schema": {"type": "object", "properties": {
         "flags": {"type": "array", "items": {"type": "string"}}},
         "required": ["flags"]}},
    {"name": "finish", "description": "结束本题。全部 flag 拿齐或确定无望时调用，summary 写清已确认的结论与封锁的方向。",
     "input_schema": {"type": "object", "properties": {
         "summary": {"type": "string"}}, "required": ["summary"]}},
]


def _tool_block(name: str, input_: dict, _id: str) -> dict:
    return {"type": "tool_use", "id": _id, "name": name, "input": input_}


def build_system_prompt(challenge, max_turns: int) -> str:
    """角色纪律 + 工作区说明。族级战术在 skills 里，不在主提示词里堆。"""
    return f"""你是授权 CTF 靶场里的渗透 agent（单机隔离环境）。目标：找出题目里全部 flag（平台说本题 {max(1, challenge.flag_count or 1)} 把）并交卷。

工作区（file 工具可读写）：/tmp/ws/{challenge.unique_code}/
- notes.md 过程黑板（append 记关键观察，记下来的才算数）
- todolist.md 规划待办（串行利用链在这里按依赖推进，跨轮有效）
- evidence/ 证据目录（fact/finding 必须挂证据文件才作数）

两个角色，按需切换：
- worker（默认）：认领一条 intent → 读它的族战术卡（graph op=skill）→ shell 打透 → 写回 fact（带证据）→ close_intent 收口。一次只做一条。
- planner：图上没有待验证 intent、或连续几步无新事实时切换：读 overview → 更新 todolist → 派生新 intent。

纪律：
- 走透一条路再换：同族 payload 在一条 shell 命令里用 for 循环打完；每条命令 20 秒内出结果（curl -m 8、nmap --host-timeout 20s）。
- 每轮至少产出一个可记录的东西：fact / 新入口 / 封锁依据。什么都没记就等于没干。
- 封锁（dead）必须写依据；重开封锁方向要说明新机理，换措辞再试不算。
- 疑似 flag 立刻 submit_flag，不要等确认。
- 沙箱无第三方库（requests/bs4 必 ModuleNotFoundError）；HTTP 用 curl；交互用 session。
- gunicorn/Werkzeug 对已注册路由自动应答 OPTIONS：200 + Allow 头 + Content-Length 0 不代表页面可访问。

预算：{max_turns} 个回合内完成。开始：先 graph(op=overview) 看已侦察到的资产与初始 intent，然后认领执行。"""


class AgentRunner:
    """单题 agent 循环。client 只要求实现 chat(system, messages, tools)（llm.MiniMaxClient 已满足）。"""

    def __init__(self, challenge, client, toolkit, *, workspace: Workspace,
                 asset_graph, explore: ExploreGraph, base_url: str = "",
                 max_turns: int = 90, deadline: float | None = None,
                 on_flag: Callable[[str, int, str], bool] | None = None,
                 start_step: int = 0):
        self.challenge = challenge
        self.client = client
        self.toolkit = toolkit
        self.ws = workspace
        self.asset = asset_graph
        self.explore = explore
        self.base_url = base_url
        self.max_turns = max(1, min(max_turns, MAX_TURNS_HARD))
        self.deadline = deadline or time.time() + 780
        self.on_flag = on_flag or (lambda flag, step, source: True)
        self.start_step = start_step
        self.turns = 0
        self.messages: list[dict[str, Any]] = []
        self.submitted: dict[str, bool] = {}
        self.correct_flags = 0
        self.stale_turns = 0
        self.last_role = "worker"

    # ---- 主循环 ----
    def run(self) -> dict:
        self._seed_message()
        next_role_nudge = ""
        while self.turns < self.max_turns:
            if time.time() >= self.deadline:
                emit("agent_timeout", unique_code=self.challenge.unique_code,
                     turns=self.turns)
                break
            if next_role_nudge:
                self._append_user_text(next_role_nudge)
                next_role_nudge = ""

            raw = self._chat_with_retry()
            if raw is None:
                break
            self.turns += 1
            blocks = raw.get("content") or []
            tool_uses = [b for b in blocks if b.get("type") == "tool_use"]
            assistant_entry: dict[str, Any] = {"role": "assistant", "content": blocks}
            self.messages.append(assistant_entry)

            if not tool_uses:
                # 纯文本空转：不产结果也不掉步数（模型只是想了想），注入提醒
                text = "\n".join(b.get("text", "") for b in blocks
                                 if b.get("type") == "text")
                emit("agent_idle_text", unique_code=self.challenge.unique_code,
                     turns=self.turns, text=text[:160])
                self._gc()
                next_role_nudge = CONTINUE_NUDGE
                continue

            results: list[dict[str, Any]] = []
            new_facts_before = (self.explore.stats()["facts"],
                                self.asset.stats().get("entries", 0))
            try:
                for call in tool_uses:
                    results.append(self._execute(call))
            except _FinishSignal as stop:
                results.append({
                    "type": "tool_result", "tool_use_id": "final",
                    "content": f"finish: {stop}"})
                self.messages.append({"role": "user", "content": results})
                emit("agent_finish", unique_code=self.challenge.unique_code,
                     turns=self.turns, summary=str(stop)[:200])
                return self._summary()
            # 工具结果必须回写进对话，否则模型下一轮看不到自己的输出
            self.messages.append({"role": "user", "content": results})
            self._gc()

            grew = (self.explore.stats()["facts"] > new_facts_before[0]
                    or self.asset.stats().get("entries", 0) > new_facts_before[1])
            if grew:
                self.stale_turns = 0
            else:
                self.stale_turns += 1

            # 收口后回到规划；连续空转也回规划（artex 的角色切换点）
            closed = any(call["name"] == "graph"
                         and call["input"].get("op") == "close_intent"
                         for call in tool_uses)
            if self.correct_flags >= max(1, self.challenge.flag_count or 1):
                emit("agent_all_flags", unique_code=self.challenge.unique_code,
                     turns=self.turns)
                break
            if closed or self.stale_turns >= STALE_PLANNER:
                next_role_nudge = PLANNER_NUDGE
                self.stale_turns = 0
            elif self.stale_turns >= 2 and not self.explore.intents_pending():
                next_role_nudge = WORKER_NUDGE
        return self._summary()
    # ---- 对话与重试 ----
    def _chat_with_retry(self) -> dict | None:
        last_error = ""
        for attempt in range(LLM_RETRIES):
            try:
                return self.client.chat(
                    build_system_prompt(self.challenge, self.max_turns),
                    self.messages, tools=TOOLS)
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"[:200]
                emit("agent_llm_error", unique_code=self.challenge.unique_code,
                     turns=self.turns, attempt=attempt + 1, detail=last_error)
                if attempt < LLM_RETRIES - 1:
                    time.sleep(2 * (attempt + 1))
        return None

    def _seed_message(self) -> None:
        overview = self.explore.overview(asset_line=self.asset.snapshot())
        self.messages.append({"role": "user", "content": (
            f"题目 {self.challenge.unique_code} 开局。开场侦察已由代码完成，"
            f"结果都已上图：\n\n{overview}\n\n"
            "先 graph(op=overview) 核对态势，然后认领一条 intent 开始执行。"
            "hint 已在图中标注。")})
        if self.explore.stats()["pending"] == 0:
            self.explore.add_intent("recon", self.base_url or "target",
                                    "开局侦察：批量路径与入口确认", step=0)

    def _append_user_text(self, text: str) -> None:
        self.messages.append({"role": "user", "content": [{"type": "text",
                                                           "text": text}]})

    # ---- 工具执行 ----
    def _execute(self, call: dict) -> dict:
        name = call.get("name", "")
        args = call.get("input") or {}
        tool_id = call.get("id", "t0")
        started = time.time()
        try:
            output = self._dispatch(name, args)
        except _FinishSignal:
            raise
        except Exception as exc:  # noqa: BLE001
            output = f"工具异常 {type(exc).__name__}: {exc}"[:300]
        elapsed = round(time.time() - started, 2)
        output = str(output)
        state_line = (f"\n[turn {self.turns}/{self.max_turns} 剩余"
                      f"{self._seconds_left()}s | 图 {json.dumps(self._stats(), ensure_ascii=False)}]")
        if len(output) > RESULT_KEEP:
            output = output[:RESULT_KEEP] + "…[长输出已归档，关键结论请已写 fact/notes]"
        result_text = output + state_line
        emit("agent_tool", unique_code=self.challenge.unique_code,
             turns=self.turns, tool=name,
             args=json.dumps(args, ensure_ascii=False)[:200],
             output=result_text[:400], elapsed=elapsed)
        return {"type": "tool_result", "tool_use_id": tool_id,
                "content": result_text}

    def _dispatch(self, name: str, args: dict) -> str:
        if name == "shell":
            return self._do_shell(args)
        if name == "session":
            return self._do_session(args)
        if name == "file":
            return self._do_file(args)
        if name == "graph":
            return self._do_graph(args)
        if name == "submit_flag":
            return self._do_submit(args)
        if name == "finish":
            raise _FinishSignal(str(args.get("summary", ""))[:400])
        return f"未知工具 {name}；可用：shell/session/file/graph/submit_flag/finish"

    def _do_shell(self, args: dict) -> str:
        command = str(args.get("command") or "").strip()
        if not command:
            return "command 为空"
        output = self.toolkit.run("shell", {"command": command})
        # 确定性副驾驶照旧：flag 直交、入口入图（模型看不见这两步的内部）
        for flag in extract_flags(output):
            self._submit_one(flag, self.start_step + self.turns,
                             f"shell 自动提取 {command[:60]}")
        fresh = self.asset.add_entries(extract_entries(output))
        if fresh:
            emit("agent_graph_seed", unique_code=self.challenge.unique_code,
                 new_entries=len(fresh))
        return output

    def _do_session(self, args: dict) -> str:
        op = str(args.get("op") or "list").lower()
        tool_args: dict[str, Any] = {}
        if op == "start":
            tool_args = {"command": str(args.get("cmd") or "")}
        elif op == "send":
            tool_args = {"id": int(args.get("id") or 0),
                         "text": str(args.get("text") or "")}
        elif op == "read":
            tool_args = {"id": int(args.get("id") or 0),
                         "wait": float(args.get("wait") or 2)}
        elif op == "kill":
            tool_args = {"id": int(args.get("id") or 0)}
        output = self.toolkit.run(f"session_{op}" if op != "list"
                                  else "session_list", tool_args)
        return output

    def _do_file(self, args: dict) -> str:
        op = str(args.get("op") or "read")
        path = str(args.get("path") or "notes.md")
        if op == "append":
            return self.ws.append_note(str(args.get("content") or ""))
        if op == "write":
            return self.ws.write_file(path, str(args.get("content") or ""))
        return self.ws.read_file(path)

    def _do_graph(self, args: dict) -> str:
        op = str(args.get("op") or "overview")
        if op == "overview":
            return self.explore.overview(asset_line=self.asset.snapshot())
        if op == "add_intent":
            intent = self.explore.add_intent(
                str(args.get("family") or "web"), str(args.get("target") or ""),
                str(args.get("why") or ""), step=self.start_step + self.turns)
            return f"intent #{intent.id} [{intent.family}] {intent.target} 已入图"
        if op == "close_intent":
            intent = self.explore.close(
                int(args.get("intent_id") or 0),
                str(args.get("status") or "dead"),
                str(args.get("verdict") or ""), step=self.start_step + self.turns)
            if intent is None:
                return "intent_id 不存在或状态非法"
            return f"intent #{intent.id} → {intent.status}"
        if op == "add_fact":
            kind = str(args.get("kind") or "note")
            content = str(args.get("content") or "")
            fact = self.explore.add_fact(kind, content,
                                         step=self.start_step + self.turns)
            # 凭据类事实直接喂给资产图的登录尝试表
            if kind == "creds":
                self.asset.add_creds([content])
            return f"fact {fact.id} 已记录"
        if op == "add_entry":
            url = str(args.get("url") or "")
            entries = extract_entries(f"link: {url}") if url else []
            added = self.asset.add_entries(entries) if entries else []
            return (f"{len(added)} 个入口入图" if added
                    else "入口解析失败，直接写在 add_intent 的 target 里")
        if op == "auto_probe":
            return self._do_auto_probe()
        if op == "skill":
            return self._read_skill(str(args.get("skill") or args.get("family") or ""))
        return f"未知 op {op}"

    def _do_auto_probe(self) -> str:
        if not self.base_url:
            return "本题没有 HTTP 基址，auto_probe 不可用；直接 shell 打端口服务"
        for _ in range(6):
            edge = self.asset.next_edge()
            if edge is None:
                return "资产图上没有待验证边了；请派生新 intent 或跑命令探索"
            rendered = graph_exec.render(edge, self.base_url)
            if rendered is None:
                self.asset.close(edge)
                continue
            self.asset.close(edge)  # 预渲染的边执行权交给模型，标记已处理
            return f"auto_probe 预渲染命令（edge={edge.key}，可直接 shell 执行）：\n{rendered}"
        return "资产图上没有可渲染的边"

    def _read_skill(self, family: str) -> str:
        from pathlib import Path
        skill_path = Path(__file__).resolve().parent / "skills" / f"{family}.md"
        try:
            return skill_path.read_text(encoding="utf-8")
        except OSError:
            return f"没有 {family} 战术卡；可用族：recon/lfi/sqli/auth/upload/cmdi/ssti/ssrf/deser/port/flag"

    def _do_submit(self, args: dict) -> str:
        flags = [str(f).strip() for f in (args.get("flags") or []) if str(f).strip()]
        if not flags:
            return "flags 为空"
        lines = []
        for flag in flags:
            correct = self._submit_one(flag, self.start_step + self.turns, "模型交卷")
            lines.append(f"{flag[:60]} → {'correct' if correct else 'rejected'}")
        return "; ".join(lines)

    def _submit_one(self, flag: str, step: int, source: str) -> bool:
        key = flag.lower()
        if key in self.submitted:
            return self.submitted[key]
        correct = bool(self.on_flag(flag, step, source))
        self.submitted[key] = correct
        if correct:
            self.correct_flags += 1
            self.explore.add_finding(f"flag 提交成功（{source[:60]}）", flag=flag)
        else:
            self.explore.add_finding(f"flag 被平台拒绝：{flag[:60]}")
        return correct

    # ---- 杂项 ----
    def _stats(self) -> dict:
        s = self.explore.stats()
        s["entries"] = self.asset.stats().get("entries", 0)
        return s

    def _seconds_left(self) -> int:
        return max(0, int(self.deadline - time.time()))

    def _gc(self) -> None:
        keep = len(self.messages) - GC_KEEP_TAIL
        if keep <= 0:
            return
        for msg in self.messages[:keep]:
            if msg.get("role") != "user" or not isinstance(msg.get("content"), list):
                continue
            for block in msg["content"]:
                if (isinstance(block, dict) and block.get("type") == "tool_result"
                        and isinstance(block.get("content"), str)
                        and len(block["content"]) > RESULT_KEEP):
                    block["content"] = (block["content"][:250]
                                        + "…[已归档；关键结论在 notes/图/证据里]")

    def _summary(self) -> dict:
        return {
            "turns": self.turns,
            "correct_flags": self.correct_flags,
            "submitted": dict(self.submitted),
            "explore": self.explore.stats(),
        }


class _FinishSignal(Exception):
    pass
