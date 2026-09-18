"""外部工具接入配置：rayscan / poxiao / ruoyi-scan 等（以远程仓库最新版为准）。

本地可能滞后远程：接入前 git pull；运行时校验可执行文件存在性，
缺失时 Agent 会收到明确提示（不会静默失败）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from penagent.tools import ToolRegistry, ToolSpec

DEFAULT_TOOLS_JSON = Path(__file__).resolve().parent / "external_tools.json"


def load_external_tools(registry: ToolRegistry,
                        path: Optional[str | Path] = None) -> dict:
    """从 JSON 配置注册外部 CLI 工具。

    注册前校验可执行文件存在性：不可用的工具不注册（LLM 看不到，
    避免反复尝试），并在返回信息中说明。
    """
    import shutil

    p = Path(path) if path else DEFAULT_TOOLS_JSON
    if not p.exists():
        return {"loaded": 0, "note": f"配置文件缺失: {p}"}
    from penagent.envcfg import expand_deep
    data = expand_deep(json.loads(p.read_text(encoding="utf-8")))
    loaded = 0
    unavailable = []
    for name, spec in (data.get("tools") or {}).items():
        cmd = spec.get("command", [])
        first = cmd[0] if cmd else ""
        if first and not Path(first).exists() and shutil.which(first) is None:
            unavailable.append(name)
            continue
        registry.register(ToolSpec(
            name=name,
            description=spec.get("description", ""),
            kind="cli",
            parameters=spec.get("parameters", {}),
            command=cmd,
            workdir=spec.get("workdir", ""),
            timeout=int(spec.get("timeout", 600)),
            dangerous=spec.get("dangerous", False),
            positional=spec.get("positional", False),
        ))
        loaded += 1
    note = data.get("note", "")
    if unavailable:
        note += f" 未注册（本地缺失，请 git pull 后重试）: {unavailable}"
    return {"loaded": loaded, "note": note}
