"""ToolRegistry：统一工具注册表（LLM 决策后调度执行）。

工具类型：
- function：Python 函数（内置安全工具）
- cli：外部工具（rayscan/poxiao/ruoyi-scan 等），配置命令模板，
  运行时校验可执行文件存在性（本地可能滞后远程，缺失即明确提示）
- http：HTTP 接口工具

安全护栏：所有工具执行前经 Policy 校验（授权目标 + 工具白名单 + 高危动作确认）。
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass
class ToolSpec:
    name: str = ""
    description: str = ""
    kind: str = "function"            # function | cli | http
    parameters: dict = field(default_factory=dict)  # JSON Schema 子集
    fn: Optional[Callable] = None
    command: list[str] = field(default_factory=list)  # cli 模板（{args} 替换）
    workdir: str = ""
    timeout: int = 300
    dangerous: bool = False           # 高危动作（默认需确认）
    positional: bool = False          # CLI 参数按位置传递（不带 --key）

    def to_schema(self) -> dict:
        return {"name": self.name, "description": self.description,
                "parameters": self.parameters,
                "dangerous": self.dangerous}


@dataclass
class ToolResult:
    tool: str = ""
    ok: bool = True
    output: Any = ""
    error: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def schemas(self) -> list[dict]:
        return [t.to_schema() for t in self._tools.values()]

    def names(self) -> list[str]:
        return sorted(self._tools)

    # ------------------------------------------------------------------
    def execute(self, name: str, args: dict,
                confirm_high_risk: bool = True) -> ToolResult:
        spec = self._tools.get(name)
        if spec is None:
            return ToolResult(tool=name, ok=False, error=f"未知工具: {name}")
        import time

        started = time.time()
        try:
            if spec.kind == "function":
                out = spec.fn(**{k: v for k, v in args.items()
                                 if k in (spec.parameters or {})})
                result = ToolResult(tool=name, output=out)
            elif spec.kind == "cli":
                result = self._run_cli(spec, args)
            else:
                result = ToolResult(tool=name, ok=False,
                                    error=f"不支持的工具类型: {spec.kind}")
        except Exception as exc:
            result = ToolResult(tool=name, ok=False, error=str(exc))
        result.duration_ms = int((time.time() - started) * 1000)
        return result

    def _run_cli(self, spec: ToolSpec, args: dict) -> ToolResult:
        """CLI 工具执行：模板替换 + 存在性校验。"""
        cmd = []
        for part in spec.command:
            if part == "{args}":
                cmd.extend(self._cli_args(spec, args))
            else:
                cmd.append(part)
        # 可执行文件存在性校验
        first = cmd[0] if cmd else ""
        if first and not Path(first).exists() \
                and shutil.which(first) is None:
            return ToolResult(
                tool=spec.name, ok=False,
                error=(f"工具 {first} 不可用（未安装或本地版本滞后，"
                       f"请以远程仓库最新版为准）"))
        proc = subprocess.run(
            cmd, cwd=spec.workdir or None, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=spec.timeout)
        return ToolResult(tool=spec.name, ok=proc.returncode == 0,
                          output=(proc.stdout or proc.stderr)[-4000:],
                          error="" if proc.returncode == 0 else proc.stderr[-1000:])

    @staticmethod
    def _cli_args(spec: ToolSpec, args: dict) -> list[str]:
        if getattr(spec, "positional", False):
            return [str(v) for v in (args or {}).values()]
        parts = []
        for key, value in (args or {}).items():
            if isinstance(value, bool):
                if value:
                    parts.append(f"--{key}")
            else:
                parts.append(f"--{key}")
                parts.append(str(value))
        return parts
