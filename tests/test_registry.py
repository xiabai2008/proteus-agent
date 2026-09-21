"""统一工具注册中心测试。

覆盖：
- 三个来源（function / cli / mcp）的统一登记与发现
- 模式可用性过滤（声明级 + 内核实建）
- 外部 MCP server 发现：可用则登记、不可用则不登记（含端到端调用桩 server）
- 验收点：新增工具不需要改 agent.py 内核代码
- 交付配置：RayScan / Chameleon 已登记为外部 MCP server
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.mcp import PentestMCPServer
from penagent.mcp_client import MCPServerSpec, probe_server, validate_http_url
from penagent.memory import Memory
from penagent.modes import load_mode
from penagent.registry import (SOURCE_CLI, SOURCE_FUNCTION, SOURCE_MCP,
                               ToolCenter, build_center)
from penagent.tools import ToolRegistry, ToolSpec

STUB = Path(__file__).resolve().parent / "_stub_mcp_server.py"


def _stub_spec(name: str = "stub", **kw) -> MCPServerSpec:
    return MCPServerSpec(name=name, transport="stdio",
                         command=(sys.executable, str(STUB)),
                         timeout=20.0, **kw)


# ----------------------------------------------------------------------
# 1. 三来源统一登记
# ----------------------------------------------------------------------
def test_center_registers_builtins_cli_and_servers(tmp_path):
    cli_config = tmp_path / "tools.json"
    cli_config.write_text(json.dumps({"tools": {
        "demo_echo": {"description": "回显", "command": [sys.executable, "-c", "print(1)"],
                      "parameters": {}},
    }}), encoding="utf-8")

    center = ToolCenter()
    assert center.register_builtins() > 0
    center.load_external_cli(cli_config)
    center.load_mcp_servers()          # 只登记声明，不连接

    assert "port_scan" in center.names(source=SOURCE_FUNCTION)
    assert "demo_echo" in center.names(source=SOURCE_CLI)
    assert center.names(source=SOURCE_MCP) == []      # 未 discover，故为空
    entry = [e for e in center.discover() if e.name == "demo_echo"][0]
    assert entry.origin == "external_tools.json"
    assert entry.spec.kind == "cli"

    summary = center.summary()
    assert summary["by_source"][SOURCE_FUNCTION] >= 4
    assert summary["by_source"][SOURCE_CLI] == 1
    assert summary["servers"] == ["chameleon", "rayscan", "seckb"]


# ----------------------------------------------------------------------
# 2. 模式可用性过滤
# ----------------------------------------------------------------------
def test_mode_availability_declared_per_tool():
    center = ToolCenter()
    center.register_spec(ToolSpec(name="everywhere"), source=SOURCE_FUNCTION,
                         origin="test")
    center.register_spec(ToolSpec(name="ctf_only"), source=SOURCE_FUNCTION,
                         origin="test", modes=("ctf-web",))

    assert center.names(mode_id="ctf-web") == ["ctf_only", "everywhere"]
    assert center.names(mode_id="pentest-standard") == ["everywhere"]
    # 声明了模式限定的工具，在不指定模式时不可见（fail-closed）
    assert center.names(mode_id=None) == ["everywhere"]


def test_build_registry_applies_mode_availability():
    center = ToolCenter()
    center.register_spec(ToolSpec(name="everywhere"), source=SOURCE_FUNCTION,
                         origin="test")
    center.register_spec(ToolSpec(name="ctf_only"), source=SOURCE_FUNCTION,
                         origin="test", modes=("ctf-web",))
    center.register_server_tools([ToolSpec(name="server_side")])

    ctf_registry = center.build_registry(load_mode("ctf-web"))
    assert ctf_registry.names() == ["ctf_only", "everywhere"]
    pentest_registry = center.build_registry(load_mode("pentest-standard"))
    assert pentest_registry.names() == ["everywhere"]
    # 服务端能力不进内核注册表，但会出现在对外 schema 里
    assert "server_side" not in ctf_registry.names()
    assert "server_side" in [s["name"] for s in center.schemas()]


def test_mode_capability_and_declared_availability_stack(tmp_path):
    """两层过滤叠加：声明级可用性 + ModeProfile.capability。"""
    center = ToolCenter()
    center.register_spec(ToolSpec(name="http_test"), source=SOURCE_FUNCTION,
                         origin="test", modes=("ctf-web",))
    center.register_spec(ToolSpec(name="nuclei"), source=SOURCE_FUNCTION,
                         origin="test", modes=("ctf-web",))

    agent = PenAgent(center.build_registry(load_mode("ctf-web")),
                     Memory(tmp_path / "mem"),
                     EvidenceChain(tmp_path / "chain.jsonl"), LLMConfig(),
                     mode=load_mode("ctf-web"))
    names = agent.registry.names()
    assert names == ["http_test"]          # nuclei 被模式 capability 拦下


# ----------------------------------------------------------------------
# 3. 外部 MCP server：发现 / 不可用不注册 / 端到端调用
# ----------------------------------------------------------------------
def test_mcp_discovery_registers_tools():
    center = ToolCenter()
    center._servers["stub"] = _stub_spec()          # 登记声明
    report = center.discover_mcp()

    assert report["stub"] == {"registered": 2, "error": ""}
    entries = center.discover(source=SOURCE_MCP)
    assert [e.name for e in entries] == ["stub_add", "stub_echo"]
    assert all(e.origin == "stub" for e in entries)
    echo = [e for e in entries if e.remote == "echo"][0]
    assert echo.spec.kind == "mcp"
    assert echo.spec.parameters == {"text": {"type": "string"}}   # schema 透传


def test_mcp_tool_call_end_to_end():
    """注册 -> 构建注册表 -> 执行：真的走 stdio 把参数送到桩 server。"""
    center = ToolCenter()
    center._servers["stub"] = _stub_spec()
    center.discover_mcp()
    registry = center.build_registry()

    assert registry.execute("stub_echo", {"text": "hello-mcp"}).output \
        == "hello-mcp"
    assert registry.execute("stub_add", {"a": 2, "b": 3}).output == "5"


def test_mcp_unavailable_server_not_registered():
    center = ToolCenter()
    center._servers["broken"] = MCPServerSpec(
        name="broken", transport="stdio", command=("definitely-not-exists",))
    report = center.discover_mcp()

    assert report["broken"]["registered"] == 0
    assert "不存在" in report["broken"]["error"]
    assert center.names(source=SOURCE_MCP) == []
    assert any("broken" in note for note in center.summary()["notes"])


def test_mcp_http_url_boundary():
    assert validate_http_url("http://127.0.0.1:18000/mcp") is None
    assert "非法协议" in validate_http_url("file:///etc/passwd")
    assert "主机名" in validate_http_url("http:///mcp")

    center = ToolCenter()
    center._servers["bad"] = MCPServerSpec(name="bad", transport="http",
                                           url="file:///tmp/x")
    report = center.discover_mcp()
    assert report["bad"]["registered"] == 0


def test_probe_returns_reason_for_missing_command():
    tools, reason = probe_server(MCPServerSpec(name="nope", transport="stdio",
                                               command=("definitely-not-exists",)))
    assert tools == [] and reason


# ----------------------------------------------------------------------
# 4. 验收点：新增工具不需要改内核代码
# ----------------------------------------------------------------------
def test_adding_tool_requires_no_kernel_change(tmp_path):
    """配置里加一个工具 -> 内核直接可用；agent.py 源码里没有任何工具名。"""
    source = (PROJECT_ROOT / "penagent" / "agent.py").read_text(encoding="utf-8")
    for tool_name in ("nuclei", "httpx", "fscan", "stub_echo", "port_scan"):
        assert tool_name not in source, f"内核代码里硬编码了工具名 {tool_name}"

    center = ToolCenter()
    center.register_spec(ToolSpec(name="brand_new_tool",
                                  description="配置新增的工具",
                                  parameters={"host": {"type": "string"}},
                                  fn=lambda **kw: {"ok": True}),
                         source=SOURCE_FUNCTION, origin="config-test")
    center._servers["stub"] = _stub_spec()
    center.discover_mcp()

    agent = PenAgent(center.build_registry(), Memory(tmp_path / "mem"),
                     EvidenceChain(tmp_path / "chain.jsonl"), LLMConfig(),
                     policy=Policy(authorize=True))
    assert "brand_new_tool" in agent.registry.names()
    assert "stub_echo" in agent.registry.names()
    # 新工具直接进 system prompt 的工具 schema
    assert "brand_new_tool" in agent._system_prompt([])


# ----------------------------------------------------------------------
# 5. MCP Server 工具清单统一来自注册中心
# ----------------------------------------------------------------------
def test_mcp_server_surface_from_center(tmp_path):
    center = ToolCenter()
    center.register_builtins()
    center.register_spec(ToolSpec(name="injected"), source=SOURCE_FUNCTION,
                         origin="test")
    server = PentestMCPServer(data_dir=str(tmp_path), center=center)
    names = [t["name"] for t in server._tools_schema()]

    assert "injected" in names                    # 注册即出现在 MCP 工具清单
    for expected in ("pentest_run", "pentest_skills", "pentest_missions",
                     "pentest_reflect"):
        assert expected in names
    # 服务端能力不进内核执行注册表
    assert "pentest_run" not in server.registry.names()


def test_shipped_mcp_servers_config():
    """交付配置：RayScan（http）、Chameleon（stdio）与 seckb 知识库（stdio）均已登记。"""
    center = ToolCenter()
    center.load_mcp_servers()
    servers = {s.name: s for s in center.servers()}

    assert set(servers) == {"rayscan", "chameleon", "seckb"}
    assert servers["rayscan"].transport == "http"
    assert servers["rayscan"].url.endswith("/mcp")
    assert servers["rayscan"].modes == ("pentest-standard",)
    assert servers["chameleon"].transport == "stdio"
    assert servers["chameleon"].command[1:] == ("-m", "chameleon.interfaces.mcp_server")
    assert servers["chameleon"].modes == ()       # 全模式可用
    assert servers["seckb"].transport == "stdio"
    assert servers["seckb"].modes == ()           # 知识检索全模式可用（只读）
    assert servers["seckb"].command[-2:] == ("mcp",) or "seckb.cli" in " ".join(
        servers["seckb"].command)


def test_poxiao_ruoyi_stay_cli():
    """poxiao / ruoyi-scan 维持 CLI 子进程接入（不进 MCP server 清单）。"""
    center = ToolCenter()
    center.load_external_cli()
    kinds = {e.name: e.spec.kind for e in center.discover(source=SOURCE_CLI)}

    assert kinds.get("poxiao_scan") == "cli"
    assert kinds.get("ruoyi_scan") == "cli"
    assert "rayscan" not in center.names(source=SOURCE_CLI)
    # poxiao/ruoyi 未出现在 MCP server 声明里
    assert not any(s.name in ("poxiao", "ruoyi-scan") for s in center.servers())


# ----------------------------------------------------------------------
# R-14：外部 MCP Server 的接入开关
#
# 现状：build_center() 只 load_mcp_servers()（登记声明），从不 discover_mcp()
# （实际连接），于是 mcp_servers.json 声明的 seckb / rayscan / chameleon
# 在**生产路径**全部不可用（唯一调用点在探针脚本与测试里）。
# 默认不连接是为避免启动被不可达的外部服务拖住——取舍合理，但需要一个
# **显式开关**，而不是让这些能力永远悬空。
# ----------------------------------------------------------------------
def test_build_center_default_does_not_connect_external_servers(monkeypatch):
    """默认（discover_mcp 未开）不得连接外部 server：启动不被拖住。"""
    from penagent import registry as reg_mod

    calls = []

    def _spy(self, name=None, probe=None):
        calls.append(name)
        return {}

    monkeypatch.setattr(reg_mod.ToolCenter, "discover_mcp", _spy)
    reg_mod.build_center()
    assert calls == []


def test_build_center_discover_flag_connects_external_servers(monkeypatch):
    """显式开启时才连接；name=None 表示连接全部已声明的 server。"""
    from penagent import registry as reg_mod

    calls = []

    def _spy(self, name=None, probe=None):
        calls.append(name)
        return {}

    monkeypatch.setattr(reg_mod.ToolCenter, "discover_mcp", _spy)
    reg_mod.build_center(discover_mcp=True)
    assert calls == [None]
