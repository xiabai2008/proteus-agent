"""统一工具注册中心：所有能力在这里登记，内核与 MCP Server 都从这里取。

每个工具登记时声明三件事：
- ``source``：能力形态——function（内核内置/服务端能力）/ cli（外部命令行）/
  mcp（外部 MCP Server 工具）
- ``origin``：具体来源（builtin / external_tools.json / rayscan / chameleon /
  server），便于审计"这个工具从哪来"
- ``modes``：模式可用性——空元组 = 全模式可用；非空 = 仅列出的模式可见

新增一个工具 = 改配置（``external_tools.json`` / ``mcp_servers.json``）或注册
一个 spec，**不需要改 agent.py 内核代码**：内核拿到的只是本中心过滤后的
ToolRegistry。

模块过滤分两层，各司其职：本中心管"工具声明的模式可用性"，
``ModeProfile.capability`` 管"模式对工具的 allow/deny 裁决"。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from penagent.builtin_tools import register_builtins
from penagent.external_tools import (DEFAULT_TOOLS_JSON,
                                     load_external_tools)
from penagent.mcp_client import (MCPClient, MCPServerSpec, probe_server)
from penagent.tools import ToolRegistry, ToolSpec

SOURCE_FUNCTION = "function"
SOURCE_CLI = "cli"
SOURCE_MCP = "mcp"
SOURCES = (SOURCE_FUNCTION, SOURCE_CLI, SOURCE_MCP)

DEFAULT_MCP_SERVERS_JSON = Path(__file__).resolve().parent / "mcp_servers.json"


@dataclass(frozen=True)
class ToolEntry:
    """注册中心里的一条工具登记。"""

    name: str
    source: str                    # function | cli | mcp
    origin: str                    # builtin | external_tools.json | <server name> | server
    spec: ToolSpec
    modes: tuple[str, ...] = ()    # 模式可用性：空 = 全模式
    kernel: bool = True            # 是否进入内核 ReAct 循环的注册表
    remote: str = ""               # mcp 来源：远端工具名

    def available_in(self, mode_id: Optional[str]) -> bool:
        if not self.modes:
            return True
        return mode_id is not None and mode_id in self.modes

    def to_meta(self) -> dict:
        return {"name": self.name, "source": self.source, "origin": self.origin,
                "modes": list(self.modes), "kernel": self.kernel,
                "remote": self.remote,
                "dangerous": bool(getattr(self.spec, "dangerous", False))}


def _specs_from(registry: ToolRegistry) -> list[ToolSpec]:
    return [registry.get(name) for name in registry.names()]


class ToolCenter:
    """统一注册中心（登记 -> 发现 -> 按模式构建注册表）。"""

    def __init__(self) -> None:
        self._entries: dict[str, ToolEntry] = {}
        self._servers: dict[str, MCPServerSpec] = {}
        self._notes: list[str] = []

    # ------------------------------------------------------------------
    # 登记
    def register_spec(self, spec: ToolSpec, *, source: str, origin: str,
                      modes: Iterable[str] = (), kernel: bool = True,
                      remote: str = "") -> ToolEntry:
        if source not in SOURCES:
            raise ValueError(f"未知工具来源 {source!r}（可用 {SOURCES}）")
        entry = ToolEntry(name=spec.name, source=source, origin=origin,
                          spec=spec, modes=tuple(modes), kernel=kernel,
                          remote=remote)
        self._entries[spec.name] = entry
        return entry

    def register_builtins(self) -> int:
        registry = ToolRegistry()
        register_builtins(registry)
        for spec in _specs_from(registry):
            self.register_spec(spec, source=SOURCE_FUNCTION, origin="builtin")
        return len(registry.names())

    def register_server_tools(self, specs: Iterable[ToolSpec],
                              origin: str = "server") -> int:
        """登记服务端高层能力（pentest_*）：只暴露给 MCP 客户端，不进内核循环。"""
        count = 0
        for spec in specs:
            self.register_spec(spec, source=SOURCE_FUNCTION, origin=origin,
                               kernel=False)
            count += 1
        return count

    def load_external_cli(self, path: Optional[str | Path] = None) -> dict:
        """从 external_tools.json 登记 CLI 工具（沿用"不可用不注册"语义）。"""
        probe = ToolRegistry()
        info = load_external_tools(probe, path or DEFAULT_TOOLS_JSON)
        for spec in _specs_from(probe):
            self.register_spec(spec, source=SOURCE_CLI,
                               origin="external_tools.json")
        if info.get("note"):
            self._notes.append(str(info["note"]))
        return info

    def load_cli_config(self, path: str | Path, *,
                        origin: Optional[str] = None,
                        default_modes: Iterable[str] = ()) -> dict:
        """按 CLI 工具 JSON 登记（在 external_tools.json 的 schema 上扩展）：

        - ``modes``：模式可用性（缺省取 default_modes）
        - 参数级 ``flag``：覆盖默认的 ``--key`` 渲染（如 RsaCtfTool 的 -n/-e）
        - 命令里的 ``{python}``：展开为当前解释器
        可执行文件不存在的工具不登记（与外部 CLI 一致，缺失即明确提示）。
        """
        import json
        import shutil
        import sys

        p = Path(path)
        if not p.is_file():
            self._notes.append(f"工具配置缺失: {p}")
            return {"loaded": 0, "note": f"配置文件缺失: {p}"}
        data = json.loads(p.read_text(encoding="utf-8"))
        label = origin or p.name
        loaded, unavailable = 0, []
        for name, block in (data.get("tools") or {}).items():
            command = [str(part).replace("{python}", sys.executable)
                       for part in (block.get("command") or [])]
            first = command[0] if command else ""
            if first and not Path(first).exists() and shutil.which(first) is None:
                unavailable.append(name)
                continue
            parameters = {k: dict(v) for k, v in
                          (block.get("parameters") or {}).items()}
            arg_flags = {}
            for key, schema in parameters.items():
                if "flag" in schema:
                    arg_flags[key] = str(schema.pop("flag"))
            self.register_spec(
                ToolSpec(name=name,
                         description=block.get("description", ""),
                         kind="cli",
                         parameters=parameters,
                         command=command,
                         workdir=block.get("workdir", ""),
                         timeout=int(block.get("timeout", 300)),
                         dangerous=bool(block.get("dangerous", False)),
                         positional=bool(block.get("positional", False)),
                         arg_flags=arg_flags,
                         sandbox=str(block.get("sandbox", "") or ""),
                         network=bool(block.get("network", False))),
                source=SOURCE_CLI, origin=label,
                modes=block.get("modes", default_modes))
            loaded += 1
        note = data.get("note", "")
        if unavailable:
            note += f" 未注册（本地缺失）: {unavailable}"
        if note:
            self._notes.append(str(note))
        return {"loaded": loaded, "note": note, "origin": label}

    def load_mcp_servers(self, path: Optional[str | Path] = None) -> dict:
        """登记外部 MCP Server 声明（只登记，不连接）。"""
        p = Path(path) if path else DEFAULT_MCP_SERVERS_JSON
        if not p.exists():
            self._notes.append(f"MCP server 配置缺失: {p}")
            return {"servers": 0, "note": f"配置文件缺失: {p}"}
        data = json.loads(p.read_text(encoding="utf-8"))
        count = 0
        for name, block in (data.get("servers") or {}).items():
            self._servers[name] = MCPServerSpec.from_dict(name, block)
            count += 1
        note = data.get("note", "")
        if note:
            self._notes.append(str(note))
        return {"servers": count, "note": note}

    # ------------------------------------------------------------------
    # 发现
    def discover(self, *, source: Optional[str] = None,
                 origin: Optional[str] = None,
                 mode_id: Optional[str] = None,
                 kernel: Optional[bool] = None) -> list[ToolEntry]:
        entries = []
        for entry in self._entries.values():
            if source is not None and entry.source != source:
                continue
            if origin is not None and entry.origin != origin:
                continue
            if kernel is not None and entry.kernel != kernel:
                continue
            if not entry.available_in(mode_id):
                continue
            entries.append(entry)
        return sorted(entries, key=lambda e: (e.source, e.name))

    def names(self, **kw) -> list[str]:
        return [e.name for e in self.discover(**kw)]

    def servers(self) -> list[MCPServerSpec]:
        return list(self._servers.values())

    def summary(self) -> dict:
        counts = {src: 0 for src in SOURCES}
        for entry in self._entries.values():
            counts[entry.source] += 1
        return {"tools": len(self._entries), "by_source": counts,
                "servers": sorted(self._servers), "notes": list(self._notes)}

    def discover_mcp(self, name: Optional[str] = None,
                     probe: Callable = probe_server) -> dict:
        """连接外部 MCP Server 并把其工具登记进来（不可用则登记失败原因）。

        probe 可注入（测试用桩），默认走真实 stdio/http 探测。
        阻塞式：仅在显式调用时发生，内核启动不隐式连接外部服务。
        """
        targets = ([self._servers[name]] if name else list(self._servers.values()))
        report: dict[str, dict] = {}
        for spec in targets:
            tools, reason = probe(spec)
            if reason:
                report[spec.name] = {"registered": 0, "error": reason}
                self._notes.append(f"MCP server {spec.name} 未注册: {reason}")
                continue
            for tool in tools:
                self._register_mcp_tool(spec, tool)
            report[spec.name] = {"registered": len(tools), "error": ""}
        return report

    def _register_mcp_tool(self, server: MCPServerSpec, tool: dict) -> None:
        remote = str(tool.get("name", ""))
        if not remote:
            return
        overrides = getattr(server, "tool_overrides", {}) or {}
        override = overrides.get(remote, {}) if isinstance(overrides, dict) else {}
        schema = tool.get("inputSchema") or {}
        parameters = schema.get("properties") if isinstance(schema, dict) else {}
        spec = ToolSpec(
            name=f"{server.name}_{remote}",
            description=str(tool.get("description", "")
                            or f"{server.description or server.name}::{remote}"),
            kind="mcp",
            parameters=parameters or {},
            fn=_mcp_caller(server, remote),
            timeout=int(getattr(server, "timeout", 30)),
            dangerous=bool(override.get("dangerous",
                                        getattr(server, "dangerous", False))),
        )
        self.register_spec(
            spec, source=SOURCE_MCP, origin=server.name,
            modes=override.get("modes", server.modes), remote=remote)

    # ------------------------------------------------------------------
    # 输出
    def build_registry(self, mode=None, *, kernel_only: bool = True,
                       sandbox=None) -> ToolRegistry:
        """按模式可用性构建内核注册表（capability 裁决由 ModeProfile 负责）。

        模式带 sandbox 档位时，注册表同时挂上沙箱策略——执行前裁决由注册表
        内部完成，调用方绕不过去。sandbox 参数可显式覆盖（测试注入用）。
        """
        from penagent.sandbox import build_sandbox

        mode_id = getattr(mode, "id", None)
        level = getattr(mode, "sandbox", None)
        if sandbox is None and level:
            sandbox = build_sandbox(level)
        registry = ToolRegistry(sandbox=sandbox)
        for entry in self.discover(mode_id=mode_id):
            if kernel_only and not entry.kernel:
                continue
            registry.register(entry.spec)
        return registry

    def schemas(self, mode=None, *, kernel_only: bool = False) -> list[dict]:
        """导出工具 schema（MCP Server 的工具清单从这里生成）。"""
        mode_id = getattr(mode, "id", None)
        return [e.spec.to_schema()
                for e in self.discover(mode_id=mode_id)
                if e.kernel or not kernel_only]


def _mcp_caller(server: MCPServerSpec, remote: str) -> Callable:
    """外部 MCP 工具的调用闭包：每次调用建连、用完即杀，不留常驻进程。"""

    def call(**kwargs):
        with MCPClient(server) as client:
            return client.call_tool(remote, kwargs)

    return call


DEFAULT_CTF_TOOLS_JSON = Path(__file__).resolve().parent / "ctf_tools.json"


def build_center(*, with_builtins: bool = True, with_external_cli: bool = True,
                 with_mcp_servers: bool = True,
                 with_ctf_tools: bool = True) -> ToolCenter:
    """组装默认注册中心（登记 + 声明；不连接外部 MCP Server）。"""
    from penagent.ctf_tools import register_ctf_tools

    center = ToolCenter()
    if with_builtins:
        center.register_builtins()
    if with_external_cli:
        center.load_external_cli()
    if with_ctf_tools:
        register_ctf_tools(center)
        center.load_cli_config(DEFAULT_CTF_TOOLS_JSON, origin="ctf_tools.json")
    if with_mcp_servers:
        center.load_mcp_servers()
    return center
