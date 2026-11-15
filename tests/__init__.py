"""让 `python -m unittest discover` 在未安装包的情况下也能找到 src 布局。"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
