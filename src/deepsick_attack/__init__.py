"""deepsick-attack：智能体安全攻防挑战赛攻击赛道参赛 Agent。

零第三方依赖，Python 3.10 以上可直接运行。核心架构（对齐 artex）：
- agent_loop.py   planner/worker 双角色 + 原生工具调用循环
- attack_graph.py 资产图（entry/edge 真值）
- explore_graph.py 探索图（intent/fact/finding 血缘链）
- workspace.py    状态外置（notes / todolist / evidence）
- solver.py       代码侦察打底 + agent 循环接管
"""

__version__ = "0.2.0"

from .config import ConfigError, load_policy, validate_policy

__all__ = [
    "ConfigError",
    "load_policy",
    "validate_policy",
]
