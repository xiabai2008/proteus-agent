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
