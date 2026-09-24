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
    # 按内容断言：核心 trio 必须登记 + 列表保持有序（不钉全集——清单随接入演进）
    assert {"rayscan", "chameleon", "seckb"} <= set(summary["servers"])
    assert summary["servers"] == sorted(summary["servers"])


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
    center.register_spec(ToolSpec(name="codec_decode"), source=SOURCE_FUNCTION,
                         origin="test", modes=("ctf-web",))
    center.register_spec(ToolSpec(name="nuclei"), source=SOURCE_FUNCTION,
                         origin="test", modes=("ctf-web",))

    agent = PenAgent(center.build_registry(load_mode("ctf-web")),
                     Memory(tmp_path / "mem"),
                     EvidenceChain(tmp_path / "chain.jsonl"), LLMConfig(),
                     mode=load_mode("ctf-web"))
    names = agent.registry.names()
    assert names == ["codec_decode"]       # nuclei 被模式 capability 拦下


# ----------------------------------------------------------------------
# 3. 外部 MCP server：发现 / 不可用不注册 / 端到端调用
# ----------------------------------------------------------------------
def test_mcp_discovery_registers_tools():
    center = ToolCenter()
    center._servers["stub"] = _stub_spec()          # 登记声明
    report = center.discover_mcp()

    assert report["stub"] == {"registered": 2, "error": "", "filtered": 0}
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
# 3.5 启动健壮性（P0-1，2026-09-24）
#
# 实测背景：Docker 守护不可用时，6 个容器 MCP server 的子进程 0.2s 就退出，
# 而旧实现（EOF 不唤醒等待者）让每个 server 卡满自己的 timeout，合计约 23
# 分钟——内核迟迟不进入 serve 循环，DSH 侧表现为"没有 mcp__proteus__*"。
# ----------------------------------------------------------------------
def _exiting_spec(name: str, code: int = 3, stderr: str = "") -> MCPServerSpec:
    """一启动就退出的 server（可带 stderr 输出），用于验证"立即失败"。"""
    script = ("import sys;"
              f"sys.stderr.write({stderr!r});"
              "sys.stderr.flush();"
              f"sys.exit({code})")
    return MCPServerSpec(name=name, transport="stdio",
                         command=(sys.executable, "-c", script),
                         timeout=30.0)


def test_probe_fails_fast_when_child_exits():
    """子进程退出必须立即失败（EOF 感知），不能等满 timeout。

    判据用时间上界：30s 的 timeout 下，实测旧实现耗时 >30s，新实现 <5s。
    """
    import time

    t0 = time.monotonic()
    tools, reason = probe_server(_exiting_spec("dead"))
    elapsed = time.monotonic() - t0

    assert tools == []
    assert elapsed < 5.0, f"EOF 未唤醒等待者（耗时 {elapsed:.1f}s）"
    assert "进程已退出" in reason


def test_probe_reason_carries_exit_code_and_stderr_tail():
    """失败原因要能定位：退出码 + stderr 尾巴（Docker 的报错就在 stderr 上）。"""
    tools, reason = probe_server(
        _exiting_spec("dead", code=125, stderr="docker: cannot find the file"))
    assert tools == []
    assert "退出码 125" in reason
    assert "cannot find the file" in reason


def test_discover_mcp_budget_skips_remaining_servers():
    """全局预算：耗尽后剩余 server 直接跳过，不再逐个等 timeout。"""
    import time

    center = ToolCenter()
    for name in ("s1", "s2", "s3"):
        center._servers[name] = MCPServerSpec(name=name, transport="stdio",
                                              command=(sys.executable, "-c", ""))

    def _slow_probe(spec):
        time.sleep(0.2)
        return [], ""

    report = center.discover_mcp(probe=_slow_probe, budget=0.05)

    assert report["s1"]["registered"] == 0          # 第一个被探测（超时/无响应）
    for name in ("s2", "s3"):
        assert "全局预算耗尽" in report[name]["error"]
    assert any("全局预算耗尽" in n for n in center.summary()["notes"])


def test_discover_mcp_budget_clamps_single_server_timeout():
    """剩余预算会夹住单个 server 的 timeout——最后一个 server 不能独吞 300s。"""
    center = ToolCenter()
    center._servers["s1"] = MCPServerSpec(name="s1", transport="stdio",
                                          command=(sys.executable, "-c", ""),
                                          timeout=300.0)
    seen = {}

    def _probe(spec):
        seen["timeout"] = spec.timeout
        return [], ""

    center.discover_mcp(probe=_probe, budget=1.5)
    assert 0 < seen["timeout"] <= 1.5


def test_discover_mcp_accepts_name_subset():
    """`--discover-mcp seckb,chameleon` 只连指定子集；未声明的名字记 note。"""
    center = ToolCenter()
    for name in ("a", "b", "c"):
        center._servers[name] = MCPServerSpec(name=name, transport="stdio",
                                              command=(sys.executable, "-c", ""))
    probed = []

    def _probe(spec):
        probed.append(spec.name)
        return [], ""

    report = center.discover_mcp(["a", "c"], probe=_probe)
    assert probed == ["a", "c"]
    assert set(report) == {"a", "c"}

    probed.clear()
    center.discover_mcp("b", probe=_probe)          # 单字符串写法（旧调用兼容）
    assert probed == ["b"]

    probed.clear()
    center.discover_mcp("nope", probe=_probe)
    assert probed == []
    assert any("nope" in n for n in center.summary()["notes"])


def test_normalize_discover_forms():
    """`--discover-mcp` 的写法归一：关 / 全开 / 子集 / 序列。"""
    from penagent.registry import normalize_discover

    assert normalize_discover(None) is None
    assert normalize_discover(False) is None
    assert normalize_discover("") is None
    assert normalize_discover("false") is None
    assert normalize_discover(True) == []
    assert normalize_discover("*") == []
    assert normalize_discover("all") == []
    assert normalize_discover("seckb,chameleon") == ["seckb", "chameleon"]
    assert normalize_discover(["a", "b"]) == ["a", "b"]
    assert normalize_discover(" a , ,b ") == ["a", "b"]


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
    """交付配置：核心 trio（RayScan/Chameleon/seckb）+ 容器化工具链均已登记。"""
    center = ToolCenter()
    center.load_mcp_servers()
    servers = {s.name: s for s in center.servers()}

    # 按内容断言（不钉全集——清理单随接入演进）
    assert {"rayscan", "chameleon", "seckb"} <= set(servers)
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
    # 容器化 MCP（T0/第 3 步/T2）：六个 server 均为 docker run stdio 形态
    for name in ("binwalk", "searchsploit", "capa", "cyberchef", "hexstrike",
                 "yara"):
        assert servers[name].transport == "stdio"
        assert servers[name].command[:2] == ("docker", "run")


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

    def _spy(self, name=None, probe=None, **kw):
        calls.append(name)
        return {}

    monkeypatch.setattr(reg_mod.ToolCenter, "discover_mcp", _spy)
    reg_mod.build_center()
    assert calls == []


def test_build_center_discover_flag_connects_external_servers(monkeypatch):
    """显式开启时才连接；name=None 表示连接全部已声明的 server。"""
    from penagent import registry as reg_mod

    calls = []

    def _spy(self, name=None, probe=None, **kw):
        calls.append(name)
        return {}

    monkeypatch.setattr(reg_mod.ToolCenter, "discover_mcp", _spy)
    reg_mod.build_center(discover_mcp=True)
    assert calls == [None]


def test_build_center_discover_accepts_subset_and_budget(monkeypatch):
    """`discover_mcp` 支持子集写法，且全局预算透传给 discover_mcp。"""
    from penagent import registry as reg_mod

    calls = []

    def _spy(self, name=None, probe=None, budget=None):
        calls.append((name, budget))
        return {}

    monkeypatch.setattr(reg_mod.ToolCenter, "discover_mcp", _spy)
    reg_mod.build_center(discover_mcp="seckb,chameleon", discover_budget=30.0)
    assert calls == [(["seckb", "chameleon"], 30.0)]

    calls.clear()
    reg_mod.build_center(discover_mcp="")
    assert calls == []                       # 空串 = 不发现


# ----------------------------------------------------------------------
# R-9：工具清单必须与内核实际挂载一致
#
# 此前 `agents` 自行拼装 ToolRegistry + builtins + adapters，与带模式的
# 内核注册表不一致（看不到 CTF 工具、不反映 capability 裁决）；而适配层
# 又只在 CLI 路径注册，DSH/MCP 路径看不到。两处都统一到 build_center。
# ----------------------------------------------------------------------
def test_build_center_adapters_toggle():
    """with_adapters 开关生效：关掉后适配层（packetforge/rayscan）不在登记里。"""
    off = build_center(with_adapters=False).all_entries()
    assert all(e.origin not in ("packetforge", "rayscan") for e in off)


def test_all_entries_not_filtered_by_mode():
    """all_entries() 返回完整登记（含仅限特定模式的 CTF 工具）。"""
    all_names = {e.name for e in build_center().all_entries()}
    assert "rsactf_attack" in all_names      # 仅在 ctf-* 模式挂载
    assert "port_scan" in all_names          # 全模式


def test_agents_listing_matches_kernel_registry(tmp_path):
    """`agents --mode` 的算法必须与内核实际注册表逐名一致（R-9）。

    两层过滤都要生效：`entry.modes`（工具声明的模式可用性）+
    `ModeProfile.capability`（模式对工具的裁决）。漏任一层都会虚报可用工具
    （实测过：只按 entry.modes 过滤时 ctf-crypto 虚报 29 个，实际 5 个）。
    """
    from penagent.agent import PenAgent, Policy
    from penagent.evidence import EvidenceChain
    from penagent.llm import LLMConfig
    from penagent.memory import Memory
    from penagent.modes import load_mode

    center = build_center()
    for mid in ("ctf-crypto", "ctf-web", "pentest-standard", None):
        mode = load_mode(mid) if mid else None
        registry = center.build_registry(mode)
        if mode is not None:
            registry = mode.filtered_registry(registry)   # cmd_agents 的算法
        agent = PenAgent(registry, Memory(tmp_path / (mid or "nomode")),
                         EvidenceChain(tmp_path / f"{mid or 'nomode'}.jsonl"),
                         LLMConfig(),
                         policy=Policy(allowed_targets=["127.0.0.1"]),
                         mode=mode)
        assert set(registry.names()) == set(agent.registry.names()), mid


# ----------------------------------------------------------------------
# 工具面白名单（tool_filter，规划 §三-1）
# ----------------------------------------------------------------------
def _fake_tools():
    return ([{"name": n, "description": f"t-{n}", "inputSchema": {"type": "object"}}
             for n in ("load_binary", "kill_process", "run_command")], "")


def _filtered_center(tool_filter):
    from penagent.mcp_client import MCPServerSpec

    center = ToolCenter()
    center._servers["fake"] = MCPServerSpec(name="fake", transport="stdio",
                                            command=("x",),
                                            tool_filter=tool_filter)
    return center


def test_tool_filter_allow_narrows_registration():
    """allow 非空：只注册列表内工具，其余被过滤（大工具面接入的前提）。"""
    center = _filtered_center({"allow": ["load_binary", "run_command"]})
    report = center.discover_mcp("fake", probe=lambda spec: _fake_tools())

    assert report["fake"]["registered"] == 2
    assert report["fake"]["filtered"] == 1
    names = center.names(source=SOURCE_MCP)
    assert "fake_load_binary" in names and "fake_run_command" in names
    assert "fake_kill_process" not in names


def test_tool_filter_deny_wins_over_allow():
    """deny 优先于 allow：同名同时出现在两边 = 不注册。"""
    center = _filtered_center({"allow": ["load_binary", "kill_process"],
                               "deny": ["kill_process"]})
    report = center.discover_mcp("fake", probe=lambda spec: _fake_tools())

    assert report["fake"]["registered"] == 1
    assert "fake_kill_process" not in center.names(source=SOURCE_MCP)


def test_tool_filter_absent_registers_everything():
    """无 tool_filter：全量注册（现有行为不变）。"""
    center = _filtered_center({})
    report = center.discover_mcp("fake", probe=lambda spec: _fake_tools())

    assert report["fake"]["registered"] == 3
    assert report["fake"]["filtered"] == 0
