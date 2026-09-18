"""ToolRegistry：统一工具注册表（LLM 决策后调度执行）。

工具类型：
- function：Python 函数（内置安全工具）
- cli：外部工具（rayscan/poxiao/ruoyi-scan 等），配置命令模板，
  运行时校验可执行文件存在性（本地可能滞后远程，缺失即明确提示）
- http：HTTP 接口工具

安全护栏：所有工具执行前经**闸门**（目标白名单 + 高危授权 + 协议白名单，
`penagent/policy_gate.py`）与**沙箱**（`penagent/sandbox.py`）两道裁决——两者都由
注册表持有，裁决发生在 `execute()` 内部，任何调用方都绕不过去。
"""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# 模式冻结参数（Policy.capability.constraints）在 args 中的保留键：
# 值为命令行 token 串，CLI 工具执行时按原样追加到命令尾部；函数型工具
# 入参按 spec.parameters 过滤，本键不会传入函数。
FROZEN_ARGS_KEY = "_frozen_args"


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
    arg_flags: dict = field(default_factory=dict)   # 参数名 -> 自定义 flag
    #    有些 CLI 只认单横线或专有写法（如 RsaCtfTool 的 -n/-e），
    #    在配置里声明 flag 即可，无需改内核渲染逻辑
    sandbox: str = ""                 # 该工具要求的隔离级别（"" = 无要求）
    network: bool = False             # 容器执行时是否需要出网（默认断网）

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
    def __init__(self, sandbox: Optional["SandboxPolicy"] = None,
                 gate: Optional["PolicyGate"] = None) -> None:
        self._tools: dict[str, ToolSpec] = {}
        # 沙箱策略由注册表持有：执行前裁决发生在 execute 内部，
        # 任何调用方（内核循环 / MCP 入口）都无法绕过
        self.sandbox = sandbox
        # 闸门（目标白名单 + 高危授权 + 协议白名单）同理由注册表持有：
        # 无论调用来自 ReAct 循环、MCP 底层工具还是 Web 子进程，都先过闸门
        self.gate = gate

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def schemas(self) -> list[dict]:
        return [t.to_schema() for t in self._tools.values()]

    def names(self) -> list[str]:
        return sorted(self._tools)

    def copy(self, *, gate: Optional["PolicyGate"] = None) -> "ToolRegistry":
        """复制一份注册表（工具集相同），可换装闸门。

        用途：同一进程内为**一次任务**派生独立护栏（例如 MCP 的 pentest_run
        需要按调用参数放大授权），而不去改动共享注册表的策略——直接改共享
        对象会让一次调用的授权永久留在服务端，属于权限放大。
        gate=None 表示沿用当前闸门；传 PolicyGate 则换装。
        """
        clone = ToolRegistry(sandbox=self.sandbox,
                             gate=self.gate if gate is None else gate)
        clone._tools = dict(self._tools)
        return clone

    # ------------------------------------------------------------------
    def execute(self, name: str, args: dict,
                confirm_high_risk: bool = True) -> ToolResult:
        spec = self._tools.get(name)
        if spec is None:
            return ToolResult(tool=name, ok=False, error=f"未知工具: {name}")
        import time

        if self.gate is not None:
            decision = self.gate.check(spec, args)
            if not decision.allowed:
                # 闸门拒绝：工具体一次都不执行（硬规则 1/3）
                return ToolResult(tool=name, ok=False, error=decision.reason)

        wrapper = None
        if self.sandbox is not None:
            decision = self.sandbox.decide(spec)
            if not decision.allowed:
                # 沙箱裁决拒绝：不执行、不降级直跑（硬规则 1/3）
                return ToolResult(tool=name, ok=False, error=decision.reason)
            wrapper = decision.wrap

        started = time.time()
        try:
            if spec.kind == "function":
                out = spec.fn(**{k: v for k, v in args.items()
                                 if k in (spec.parameters or {})})
                result = ToolResult(tool=name, output=out)
            elif spec.kind == "mcp":
                # 外部 MCP Server 工具：参数按远端 schema 原样透传；
                # 模式冻结参数是 CLI 概念，不带给远端
                call_args = {k: v for k, v in (args or {}).items()
                             if k != FROZEN_ARGS_KEY}
                result = ToolResult(tool=name, output=spec.fn(**call_args))
            elif spec.kind == "cli":
                result = self._run_cli(spec, args, wrapper)
            else:
                result = ToolResult(tool=name, ok=False,
                                    error=f"不支持的工具类型: {spec.kind}")
        except Exception as exc:
            result = ToolResult(tool=name, ok=False, error=str(exc))
        result.duration_ms = int((time.time() - started) * 1000)
        return result

    def _run_cli(self, spec: ToolSpec, args: dict, wrapper=None) -> ToolResult:
        """CLI 工具执行：模板替换 + 存在性校验（容器执行时由 wrapper 接管）。"""
        cmd = []
        for part in spec.command:
            if part == "{args}":
                cmd.extend(self._cli_args(spec, args))
            else:
                cmd.append(part)
        if wrapper is not None:
            # 容器执行：可执行文件在镜像内，宿主存在性校验不适用
            cmd = wrapper(cmd)
        else:
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
        # 模式冻结参数单独拎出：按原样追加在命令尾部（不参与 --key 渲染）
        args = args or {}
        frozen = str(args.get(FROZEN_ARGS_KEY, "") or "").strip()
        params = {k: v for k, v in args.items() if k != FROZEN_ARGS_KEY}
        if getattr(spec, "positional", False):
            parts = [str(v) for v in params.values()]
        else:
            parts = []
            for key, value in params.items():
                flag = (getattr(spec, "arg_flags", None) or {}).get(
                    key, f"--{key}")
                if isinstance(value, bool):
                    if value:
                        parts.append(flag)
                else:
                    parts.append(flag)
                    parts.append(str(value))
        if frozen:
            parts.extend(shlex.split(frozen))
        return parts
