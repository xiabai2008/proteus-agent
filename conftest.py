"""pytest 会话配置：解析外部依赖 07-agent-war-range 的位置。

内核的回归评测脚本（examples/*.py）需要 07 靶场的 warfare 仿真包。
按项目约定（AGENTS.md 第 7 条），外部项目按绝对路径引用、不做 vendoring。

路径优先级：
  1. 环境变量 PENTEST_G07_ROOT
  2. 相邻项目布局（内核置于 07 同级的开发目录时）
  3. 本机已知绝对路径

解析结果同时注入 PYTHONPATH，供 tests 以 subprocess 拉起的评测脚本继承。
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

CANDIDATES = [
    ROOT.parent / "07-agent-war-range",
    Path(r"<WS>\网安项目开发规划\07-agent-war-range"),
]


def _resolve_g07() -> "Path | None":
    env = os.environ.get("PENTEST_G07_ROOT")
    if env and (Path(env) / "warfare").is_dir():
        return Path(env)
    for candidate in CANDIDATES:
        if (candidate / "warfare").is_dir():
            return candidate
    return None


G07 = _resolve_g07()

if G07 is not None:
    if str(G07) not in sys.path:
        sys.path.insert(0, str(G07))
    _existing = os.environ.get("PYTHONPATH", "")
    _parts = [str(G07)] + ([_existing] if _existing else [])
    os.environ["PYTHONPATH"] = os.pathsep.join(_parts)
