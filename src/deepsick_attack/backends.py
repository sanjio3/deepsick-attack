"""可替换后端：模型、执行器与提示注入。

赛场接入时只替换这里的两个类，主循环与判定器不需要改。
OfflineLLM / OfflineExecutor 仅用于离线自检，不发起任何网络请求。
"""
from __future__ import annotations

from .config import PROMPT_DIR
from .models import Hint, Intent
from .stage_runner import StageRunner


def load_prompt(name: str) -> str:
    return (PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8")


class LLMClient:
    """赛场替换点一：把 propose_action 换成真实模型调用。

    模型负责把阶段动作模板展开成具体命令，不负责选阶段、不负责判定完成。
    """

    def __init__(self):
        self.planner_prompt = load_prompt("planner")
        self.worker_prompt = load_prompt("worker")
        self.auditor_prompt = load_prompt("auditor")

    def propose_action(self, stage: dict, template: str, state: dict) -> str:
        raise NotImplementedError


class OfflineLLM(LLMClient):
    def propose_action(self, stage: dict, template: str, state: dict) -> str:
        return template


class Executor:
    """赛场替换点二：换成授权范围内的确定性 CLI 执行器。

    每一步必须产生真实网络请求或命令输出。平台侧靠流量与审计日志还原路径，
    本地写一份好看的轨迹不能替代真实动作。
    """

    def execute(self, intent: Intent, replay: bool = False) -> dict:
        raise NotImplementedError


class OfflineExecutor(Executor):
    """自检后端：预设观测，不发起任何真实网络请求。"""

    OBS = {
        "recon": "open ports: 80, 8080",
        "fingerprint": "Server: demo-component 1.0",
        "vuln": "candidate entry: /demo/endpoint",
        "exploit": "200 OK, response body captured",
        "flag": "flag{DEMO_ONLY_NOT_A_REAL_FLAG}",
        "submit": "ACCEPTED by offline stub",
    }

    def __init__(self, fail_once_on: str | None = None):
        self.fail_once_on = fail_once_on
        self._failed: set[str] = set()

    def execute(self, intent: Intent, replay: bool = False) -> dict:
        text = self.OBS.get(intent.stage, "no output")
        if (self.fail_once_on == intent.stage
                and intent.stage not in self._failed
                and not replay):
            self._failed.add(intent.stage)
            text = "connection refused"
        if replay and intent.stage == "flag":
            text = "flag{DEMO_ONLY_NOT_A_REAL_FLAG} (independent replay)"
        command = f"[offline] {intent.action}"
        if replay:
            command += " --independent-replay"
        return {"source_kind": "tool_output", "output": text, "command": command}


class HintEngine:
    """替代人工纠偏：阶段内备选手段用尽时，自动注入 playbook 提示。"""

    def __init__(self, runner: StageRunner):
        self.runner = runner
        self.injected: set[str] = set()

    def inject(self, stage_id: str, state: dict):
        if stage_id in self.injected:
            return None
        text = self.runner.hint_for(stage_id)
        if not text:
            return None
        self.injected.add(stage_id)
        return Hint(
            id=f"h{len(state['hints']) + 1}",
            stage=stage_id,
            text=text,
            source="playbook",
        )
