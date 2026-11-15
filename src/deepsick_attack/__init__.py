"""deepsick-attack：智能体安全攻防挑战赛攻击赛道参赛 Agent。

零第三方依赖，Python 3.10 以上可直接运行。正式赛场只需替换
backends.py 里的 LLMClient 与 Executor 两个实现。
"""

__version__ = "0.1.0"

from .agent import run_target, self_test
from .config import ConfigError, load_policy, validate_policy
from .path_score import PathMatcher
from .stage_runner import StageRunner

__all__ = [
    "ConfigError",
    "PathMatcher",
    "StageRunner",
    "load_policy",
    "run_target",
    "self_test",
    "validate_policy",
]
