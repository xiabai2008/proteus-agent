"""环境配置助手：.env 装载 + `${VAR}` 占位符展开。

本仓库的可移植性约定（公开仓库不含任何本机路径）：
- 配置 JSON（external_tools.json / mcp_servers.json / ctf_tools.json）里
  一律写 `${PENTEST_WS}` / `${PENTEST_TOOLS}` 等占位符；
- 真实路径放在**不入库**的 `.env`（PENTEST_WS / PENTEST_TOOLS / PENTEST_PY312 /
  PENTEST_G07_ROOT），加载配置时在此展开；
- 未设置的环境变量保持原样（便于运行时存在性校验给出"未注册"而非崩溃）。
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def read_env_file(path: Path = ENV_FILE) -> dict[str, str]:
    """解析 KEY=VALUE 行（忽略 # 注释与空行），不入库的本地配置来源。"""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


def load_env_file(path: Path = ENV_FILE) -> int:
    """把 .env 的键注入 os.environ（不覆盖已存在的同名环境变量）。

    返回注入的键数。模块导入方（conftest / 配置装载器）调用它，保证
    `${VAR}` 展开与 G07 解析在"只在 .env 里配了路径"的机器上也能工作。
    """
    injected = 0
    for k, v in read_env_file(path).items():
        if k not in os.environ:
            os.environ[k] = v
            injected += 1
    return injected


def expand(value: str) -> str:
    """展开字符串里的 ${VAR}；未定义的变量原样保留。"""
    return _VAR.sub(
        lambda m: os.environ.get(m.group(1), m.group(0)), value)


def expand_deep(obj):
    """递归展开 dict / list / str 里的 ${VAR}（其余类型原样返回）。"""
    if isinstance(obj, str):
        return expand(obj)
    if isinstance(obj, dict):
        return {k: expand_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_deep(v) for v in obj]
    return obj


# ----------------------------------------------------------------------
# 本机路径清单（硬规则 7：入库文件不得含本机绝对路径）
#
# 清洗工具（tools/scrub_paths.py）与回归用例（tests/test_path_hygiene.py）
# 共用这一份解析——两处各写一遍必然漂移（与 resolve_g07 同款理由）。
# ----------------------------------------------------------------------
def local_needles() -> tuple[tuple[str, str], ...]:
    """(本机绝对路径, 占位符) 列表，按路径长度降序。

    来源：仓库根（运行时解析）、用户主目录、`.env` 里的 PENTEST_* 路径。
    未配置的变量不产生条目——清洗与校验都不该依赖某台机器的配置。
    长度降序是必要的：先替长的，父路径才不会把子路径截断成一半。
    """
    load_env_file()
    pairs: list[tuple[str, str]] = [(str(PROJECT_ROOT), "<REPO>")]
    home = Path.home()
    if str(home) not in ("", "."):
        pairs.append((str(home), "<USER_HOME>"))
    for var, placeholder in (("PENTEST_WS", "<WS>"),
                             ("PENTEST_TOOLS", "<TOOLS_DIR>"),
                             ("PENTEST_PY312", "<PY312>"),
                             ("PENTEST_G07_ROOT", "<G07_ROOT>")):
        value = os.environ.get(var, "").strip()
        if value:
            pairs.append((value, placeholder))
    unique: dict[str, str] = {}
    for value, placeholder in pairs:
        unique.setdefault(value, placeholder)
    return tuple(sorted(unique.items(), key=lambda kv: len(kv[0]),
                        reverse=True))


def local_path_pattern(value: str) -> re.Pattern[str]:
    """把一条本机路径编译成**分隔符无关、大小写不敏感**的匹配式。

    Windows 路径在文档与命令输出里两种分隔符都有，大小写也常变（实测 pip
    把整条路径输出成全小写）；文档里的转义写法还会出现**连续**分隔符。
    只按原样匹配会漏——三种形态都要认。
    """
    segments = [re.escape(seg) for seg in re.split(r"[\\/]+", value) if seg]
    return re.compile(r"[\\/]+".join(segments), re.IGNORECASE)


def scrub_local_paths(text: str) -> str:
    """把文本里的本机路径替换为占位符（未配置的路径天然不会命中）。"""
    for value, placeholder in local_needles():
        text = local_path_pattern(value).sub(placeholder, text)
    return text


def find_local_paths(text: str) -> list[str]:
    """返回文本里出现的本机路径（按 needles 顺序，供 `--check` 与用例报错）。"""
    return [value for value, _ in local_needles()
            if local_path_pattern(value).search(text)]


# ----------------------------------------------------------------------
# 外部依赖：07 靶场（warfare 仿真包）
#
# 内核的回归评测脚本（examples/eval_evolution*.py / eval_closed_loop.py）与
# 评测骨架（examples/benchmark.py）都需要它。解析逻辑放这里，让 pytest
# （conftest.py）与直跑脚本（benchmark.py）**共用同一份**，而不是各写一遍
# ——重复实现必然漂移。
# ----------------------------------------------------------------------
def g07_candidates() -> tuple[Path, ...]:
    """07 靶场的候选位置（按优先级）。"""
    return (
        PROJECT_ROOT.parent / "07-agent-war-range",
        PROJECT_ROOT.parent / "网安项目开发规划" / "07-agent-war-range",
    )


def resolve_g07() -> Optional[Path]:
    """解析 07 靶场根目录（须含 warfare 包）。

    优先级：`PENTEST_G07_ROOT` 环境变量（含 `.env` 里的）→ 相邻项目布局。
    外部项目按绝对路径引用、不 vendoring（AGENTS.md 第 7 条）。
    找不到返回 None——调用方应据此标记 skip，而不是崩溃。
    """
    load_env_file()
    env = os.environ.get("PENTEST_G07_ROOT")
    if env and (Path(env) / "warfare").is_dir():
        return Path(env)
    for candidate in g07_candidates():
        if (candidate / "warfare").is_dir():
            return candidate
    return None


def ensure_g07_on_path() -> Optional[Path]:
    """解析 07 靶场并注入 import 路径（本进程 sys.path + 子进程 PYTHONPATH）。

    PYTHONPATH 那一份是给 test 用 subprocess 拉起的评测脚本继承的。
    返回解析到的路径；未找到返回 None。
    """
    import sys

    g07 = resolve_g07()
    if g07 is None:
        return None
    if str(g07) not in sys.path:
        sys.path.insert(0, str(g07))
    existing = os.environ.get("PYTHONPATH", "")
    parts = [str(g07)] + ([existing] if existing else [])
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)
    return g07
