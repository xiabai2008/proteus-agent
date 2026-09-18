"""工具执行闸门测试：目标白名单 + 高危授权对所有入口机制性生效。

对照 docs/DSH宿主实测记录.md 的 F1 复现步骤写：此前 MCP 底层工具入口直连注册表、
不过 Policy，导致 `--targets 127.0.0.1` 下传 `127.0.0.2` / `192.168.1.1` 照样执行。
本文件把"越界目标照常执行"钉成"被闸门拒绝"。

另覆盖 DSH-F2：MCP 工具失败必须报 isError=true，禁止失败报成功（含 pentest_run）。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import Policy
from penagent.mcp import PentestMCPServer
from penagent.policy_gate import PolicyGate
from penagent.tools import ToolRegistry, ToolSpec

LOOPBACK = ["127.0.0.1"]


def _call(server, method, params=None, msg_id=1):
    line = json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method,
                       "params": params or {}})
    return json.loads(server.handle_line(line))


def _payload(response) -> object:
    blocks = response["result"]["content"]
    assert isinstance(blocks, list) and blocks[0]["type"] == "text"
    return json.loads(blocks[0]["text"])


def _gate(*, targets=None, authorize: bool = False, mode=None) -> PolicyGate:
    return PolicyGate(Policy(allowed_targets=targets, authorize=authorize,
                             mode=mode))


# ----------------------------------------------------------------------
# 1. 闸门在注册表里：任何调用方都绕不过去
# ----------------------------------------------------------------------
def test_registry_gate_blocks_before_tool_body_runs():
    """闸门拒绝时工具体不得被调用——证明裁决发生在执行之前。"""
    calls: list[dict] = []
    registry = ToolRegistry(gate=_gate(targets=LOOPBACK))
    registry.register(ToolSpec(
        name="http_probe", description="探测",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: calls.append(kw) or {"status": 200}))

    result = registry.execute("http_probe", {"url": "http://192.168.1.1/"})
    assert not result.ok
    assert calls == [], "越界目标绝不能被工具体执行"
    assert "不在授权范围" in result.error


def test_registry_gate_allows_in_scope_target():
    registry = ToolRegistry(gate=_gate(targets=LOOPBACK))
    registry.register(ToolSpec(
        name="http_probe", description="探测",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"status": 200}))

    result = registry.execute("http_probe", {"url": "http://127.0.0.1:8080/"})
    assert result.ok and result.output == {"status": 200}


@pytest.mark.parametrize("key,value", [
    ("host", "127.0.0.2"),          # 回环但不是白名单里的那个
    ("host", "192.168.1.1"),        # 私网
    ("url", "http://127.0.0.2:8080/"),
    ("url", "http://192.168.1.1/admin"),
    ("domain", "evil.example.com"),
    ("target", "http://10.0.0.5/"),
    ("base_url", "http://172.16.0.9/"),
])
def test_gate_covers_every_target_bearing_param(key, value):
    registry = ToolRegistry(gate=_gate(targets=LOOPBACK))
    registry.register(ToolSpec(
        name="probe", description="探测",
        parameters={key: {"type": "string"}},
        fn=lambda **kw: {"executed": True}))

    result = registry.execute("probe", {key: value})
    assert not result.ok, f"{key}={value} 必须被拒"
    assert "不在授权范围" in result.error


@pytest.mark.parametrize("raw,expected", [
    ("127.0.0.1", ["127.0.0.1"]),
    ("127.0.0.1,localhost", ["127.0.0.1", "localhost"]),
    (" 10.0.0.1 , 127.0.0.1 ", ["10.0.0.1", "127.0.0.1"]),
    (["127.0.0.1"], ["127.0.0.1"]),
    ("", ["127.0.0.1", "localhost"]),
    (None, ["127.0.0.1", "localhost"]),
    ([], ["127.0.0.1", "localhost"]),
])
def test_policy_normalizes_targets(raw, expected):
    """授权目标必须规范化：字符串是 iterable，`list("127.0.0.1")` 会炸成单字符，
    而匹配是 `host.endswith("." + t)`，单字符会把白名单打成筛子。"""
    assert Policy.normalize_targets(raw) == expected


def test_cli_style_string_targets_do_not_leak_single_chars():
    """CLI 的 --targets 是逗号分隔字符串：绝不能退化成单字符白名单。"""
    gate = PolicyGate(Policy(allowed_targets="127.0.0.1"))
    assert gate.policy.allowed_targets == ["127.0.0.1"]

    registry = ToolRegistry(gate=gate)
    for host in ("127.0.0.2", "192.168.1.1", "10.0.0.1"):
        registry.register(ToolSpec(name="probe", description="探测",
                                   parameters={"host": {"type": "string"}},
                                   fn=lambda **kw: {"executed": True}))
        result = registry.execute("probe", {"host": host})
        assert not result.ok, f"{host} 曾被单字符条目意外放行"
    assert registry.execute("probe", {"host": "127.0.0.1"}).ok


def test_gate_rejects_non_http_scheme():
    """协议白名单：只允许 http/https（与 mcp_client 同一约定）。"""
    registry = ToolRegistry(gate=_gate(targets=LOOPBACK))
    registry.register(ToolSpec(
        name="fetch", description="抓取",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"executed": True}))

    result = registry.execute("fetch", {"url": "file:///etc/passwd"})
    assert not result.ok
    assert "协议" in result.error or "不在授权范围" in result.error


def test_gate_denies_dangerous_tool_without_operator_authorization():
    """高危工具必须由操作员授权：调用参数据此不能自我放行。"""
    registry = ToolRegistry(gate=_gate(targets=LOOPBACK))
    registry.register(ToolSpec(
        name="web_exploit", description="利用", dangerous=True,
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"executed": True}))

    result = registry.execute("web_exploit", {"url": "http://127.0.0.1/",
                                             "authorize": True})
    assert not result.ok
    assert "未授权" in result.error
    # 操作员授权后才放行
    ok_registry = ToolRegistry(gate=_gate(targets=LOOPBACK, authorize=True))
    ok_registry.register(ToolSpec(
        name="web_exploit", description="利用", dangerous=True,
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"executed": True}))
    assert ok_registry.execute("web_exploit",
                               {"url": "http://127.0.0.1/"}).ok


def test_gate_enforces_mode_capability_when_mode_present():
    """带上模式时，capability 禁用同样在闸门处生效（不只靠注册表过滤）。"""
    from penagent.modes import load_mode

    mode = load_mode("ctf-web")            # 该模式 deny 了 http_probe 一族
    registry = ToolRegistry(gate=_gate(targets=LOOPBACK, mode=mode))
    registry.register(ToolSpec(
        name="http_probe", description="探测",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"executed": True}))

    result = registry.execute("http_probe", {"url": "http://127.0.0.1/"})
    assert not result.ok
    assert "禁用" in result.error


# ----------------------------------------------------------------------
# 2. MCP 入口：越界目标必须被拒（F1 复现步骤的用例化）
# ----------------------------------------------------------------------
@pytest.fixture()
def server(tmp_path):
    return PentestMCPServer(data_dir=str(tmp_path / "data"),
                            allowed_targets=LOOPBACK)


def test_mcp_bottom_level_rejects_out_of_scope_target(server):
    """F1 复现：--targets 127.0.0.1 下传 127.0.0.2 / 192.168.1.1 必须被拒。"""
    for host in ("127.0.0.2", "192.168.1.1"):
        r = _call(server, "tools/call",
                  {"name": "port_scan", "arguments": {"host": host,
                                                      "ports": "80"}},
                  msg_id=11)
        payload = _payload(r)
        assert payload["ok"] is False, f"{host} 不该被执行"
        assert "不在授权范围" in payload["error"]
        assert r["result"]["isError"] is True


def test_mcp_bottom_level_allows_in_scope_target(server):
    """对照组：白名单内的目标照常可用（修复不能把正常用法一起打死）。

    注意用 127.0.0.1 而不是 localhost——本 fixture 的白名单就是 ["127.0.0.1"]，
    localhost 不在其中，被拒才是对的（白名单是精确匹配，不是"回环就放行"）。
    """
    r = _call(server, "tools/call",
              {"name": "dns_lookup", "arguments": {"domain": "127.0.0.1"}},
              msg_id=12)
    payload = _payload(r)
    assert payload["ok"] is True
    assert "127.0.0.1" in payload["output"]["ips"]


def test_mcp_bottom_level_rejects_localhost_when_not_whitelisted(server):
    """白名单外的主机名同样被拒：localhost 不在 ["127.0.0.1"] 里。"""
    r = _call(server, "tools/call",
              {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
              msg_id=18)
    payload = _payload(r)
    assert payload["ok"] is False
    assert "不在授权范围" in payload["error"]


def test_mcp_bottom_level_requires_operator_authorization_for_dangerous(server):
    """高危工具走 MCP 时不能靠调用参数自我授权。"""
    r = _call(server, "tools/call",
              {"name": "web_exploit",
               "arguments": {"url": "http://127.0.0.1/", "authorize": True}},
              msg_id=13)
    # 该工具未注册时也应给出明确拒绝/未知，而不是执行
    payload = _payload(r)
    assert payload["ok"] is False


def test_mcp_server_authorize_flag_opens_dangerous_tools(tmp_path):
    """操作员显式 --authorize 后，白名单内的危险工具才放行。"""
    srv = PentestMCPServer(data_dir=str(tmp_path / "data"),
                           allowed_targets=LOOPBACK, authorize=True)
    # 直接问闸门：白名单内的高危工具在授权后应放行（不实际执行工具体）
    spec = ToolSpec(name="web_exploit", description="利用", dangerous=True,
                    parameters={"url": {"type": "string"}},
                    fn=lambda **kw: {"executed": True})
    assert srv.registry.gate.check(spec, {"url": "http://127.0.0.1/"}).allowed


# ----------------------------------------------------------------------
# 3. MCP 失败语义：禁止失败报成功
# ----------------------------------------------------------------------
def test_mcp_tool_failure_reports_iserror_true(server):
    """工具自身失败（缺必需参数）→ isError=true + 结构化错误。

    此前 isError 恒为 false，严格客户端会把失败当成功（DSH-F2）。
    """
    r = _call(server, "tools/call",
              {"name": "robots_fetch", "arguments": {"url": "http://127.0.0.1/"}},
              msg_id=14)
    assert r["result"]["isError"] is True
    payload = _payload(r)
    assert payload["ok"] is False
    assert payload["error"], "失败必须带结构化错误信息"


def test_mcp_success_still_reports_iserror_false(server):
    r = _call(server, "tools/call",
              {"name": "dns_lookup", "arguments": {"domain": "127.0.0.1"}},
              msg_id=15)
    assert r["result"]["isError"] is False


def test_mcp_unknown_tool_reports_iserror_true(server):
    r = _call(server, "tools/call",
              {"name": "ghost_tool", "arguments": {}}, msg_id=16)
    assert r["result"]["isError"] is True
    assert _payload(r)["ok"] is False


def test_mcp_pentest_run_failure_reports_iserror_true(tmp_path, monkeypatch):
    """pentest_run 失败（LLM 不可用）也必须 isError=true，且不外呼网络。

    这里把 `chat_json` 直接桩成抛 LLMError：不依赖本机 .env 是否配了 key
    （配了的话会真的外呼），也不受 examples/eval_ctf_solve 留下的全局替换影响。
    """
    from penagent.llm import LLMError

    def _boom(config, messages, **kw):
        raise LLMError("未配置 PENTEST_LLM_API_KEY（测试桩）")

    monkeypatch.setattr("penagent.agent.chat_json", _boom)
    srv = PentestMCPServer(data_dir=str(tmp_path / "data"),
                           allowed_targets=LOOPBACK)
    r = _call(srv, "tools/call",
              {"name": "pentest_run",
               "arguments": {"target": "http://127.0.0.1:8080",
                             "objective": "被动侦察"}},
              msg_id=17)
    assert r["result"]["isError"] is True, "任务失败不能被报成成功"
    payload = _payload(r)
    assert payload["outcome"] == "failed"
    assert "LLM" in payload["summary"]
