"""MCP Server 测试：协议层与工具调用。"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.mcp import PentestMCPServer


@pytest.fixture()
def server(tmp_path):
    return PentestMCPServer(data_dir=str(tmp_path / "data"))


def _call(server, method, params=None, msg_id=1):
    line = json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method,
                       "params": params or {}})
    return json.loads(server.handle_line(line))


def test_initialize(server):
    r = _call(server, "initialize")
    assert r["result"]["serverInfo"]["name"] == "xpentest"
    assert r["result"]["protocolVersion"]


def _payload(response) -> object:
    """取 MCP 规范 content 块数组里的 JSON 文本并解析回对象。"""
    blocks = response["result"]["content"]
    assert isinstance(blocks, list) and blocks[0]["type"] == "text"
    return json.loads(blocks[0]["text"])


def test_tools_list(server):
    r = _call(server, "tools/list")
    tools = {t["name"]: t for t in r["result"]["tools"]}
    assert {"port_scan", "http_probe", "dns_lookup", "robots_fetch",
            "poxiao_scan", "pentest_run", "pentest_skills",
            "pentest_missions", "pentest_reflect"} <= set(tools)
    # 官方 SDK 客户端会严格校验：inputSchema 必须存在且是 object
    for tool in tools.values():
        assert tool["inputSchema"]["type"] == "object"
        assert "parameters" not in tool          # 非规范字段不外泄


def test_tool_call_builtin(server):
    r = _call(server, "tools/call", {
        "name": "dns_lookup", "arguments": {"domain": "localhost"}}, msg_id=2)
    assert "error" not in r
    payload = _payload(r)
    assert "127.0.0.1" in payload["output"]["ips"]


def test_tool_call_unknown_tool(server):
    r = _call(server, "tools/call",
              {"name": "ghost", "arguments": {}}, msg_id=3)
    payload = _payload(r)
    assert payload["ok"] is False
    assert "未知工具" in payload["error"]


def test_pentest_skills_empty(server):
    r = _call(server, "tools/call",
              {"name": "pentest_skills", "arguments": {}}, msg_id=4)
    assert _payload(r) == []


def test_pentest_missions_empty(server):
    r = _call(server, "tools/call",
              {"name": "pentest_missions", "arguments": {}}, msg_id=5)
    assert _payload(r) == []


def test_unknown_method(server):
    r = _call(server, "bad_method", msg_id=6)
    assert r["error"]["code"] == -32601


def test_notification_returns_none(server):
    line = json.dumps({"jsonrpc": "2.0",
                       "method": "notifications/initialized", "params": {}})
    assert server.handle_line(line) is None


def test_invalid_json(server):
    r = json.loads(server.handle_line("not json"))
    assert r["error"]["code"] == -32700


def test_pentest_run_mode_param_in_schema(server):
    """pentest_run 暴露 mode 参数，描述里写明可选值（DSH 侧 LLM 靠它路由）。"""
    schema = server._tools_schema()
    spec = next(t for t in schema if t["name"] == "pentest_run")
    assert spec["inputSchema"]["properties"]["mode"] == {"type": "string"}
    for mid in ("pentest-standard", "ctf-web", "ctf-crypto"):
        assert mid in spec["description"]


def test_agent_mode_switch_registry_and_verifier(server):
    """mode_id=ctf-web：注册表按模式重建（nuclei 被拒之门外）、判定器切 flag_regex。"""
    agent = server._agent(mode_id="ctf-web")
    assert agent.mode is not None and agent.mode.id == "ctf-web"
    from penagent.verifier import FlagRegexVerifier

    assert isinstance(agent.verifier, FlagRegexVerifier)
    assert "nuclei_scan" not in agent.registry.names()


def test_agent_default_mode_keeps_evidence_chain(server):
    """不带 mode：维持升级前行为（全量注册表 + 证据链判定器）。"""
    agent = server._agent()
    assert agent.mode is None
    from penagent.verifier import EvidenceChainVerifier

    assert isinstance(agent.verifier, EvidenceChainVerifier)
    assert "http_probe" in agent.registry.names()   # 内置工具不依赖本机二进制


def test_pentest_run_unknown_mode_is_structured_error(server):
    """未知模式 id → isError=true 的结构化结果（不是协议级 error）。"""
    r = _call(server, "tools/call", {
        "name": "pentest_run",
        "arguments": {"target": "http://127.0.0.1:9", "objective": "x",
                      "mode": "ghost-mode"}}, msg_id=9)
    result = r["result"]
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is False


