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


# ----------------------------------------------------------------------
# R-1：服务端级默认模式（pentest_run 未传 mode 时的回落）
#
# 背景：mode 是 pentest_run 的**可选**参数。不传时 _agent() 走 mode=None
# 分支——沙箱裁决完全缺失（危险 CLI 工具直跑宿主）、记忆落 default 分区、
# 步数预算退回 12。但"显式要求不给模式时报错"是不可接受的（向后兼容与
# 无模式冒烟都要保留），所以修法是**服务端级 default_mode**：
# 配置了才回落，未配置保持原行为。
# ----------------------------------------------------------------------
def test_server_default_mode_applied_when_omitted(tmp_path):
    """配了 default_mode：不带 mode 调用回落到它（沙箱/预算/分区随之生效）。"""
    server = PentestMCPServer(data_dir=str(tmp_path / "data"),
                              default_mode="pentest-standard")
    agent = server._agent()
    assert agent.mode is not None and agent.mode.id == "pentest-standard"
    # 模式预算生效（无模式时是 12）
    assert agent.max_steps == 40
    # 记忆落模式分区（无模式时是 default）
    assert agent.memory.namespace == "pentest-standard"
    # 沙箱策略随模式挂上（无模式时是 None）
    assert agent.registry.sandbox is not None


def test_server_explicit_mode_overrides_default(tmp_path):
    """显式传 mode 时优先于 default_mode。"""
    server = PentestMCPServer(data_dir=str(tmp_path / "data"),
                              default_mode="pentest-standard")
    agent = server._agent(mode_id="ctf-crypto")
    assert agent.mode is not None and agent.mode.id == "ctf-crypto"


def test_server_default_mode_validated_at_construction(tmp_path):
    """default_mode 在构造期校验：未知 id 直接抛 ModeError（fail-closed）。

    配错模式名应在启动时大声失败，而不是等第一次任务才报。
    """
    from penagent.modes import ModeError

    with pytest.raises(ModeError):
        PentestMCPServer(data_dir=str(tmp_path / "data"),
                         default_mode="ghost-mode")


def test_server_without_default_mode_keeps_legacy_behavior(tmp_path):
    """未配 default_mode：保持向后兼容（mode=None，全量注册表 + 证据链判定器）。"""
    server = PentestMCPServer(data_dir=str(tmp_path / "data"))
    assert server._agent().mode is None




# ----------------------------------------------------------------------
# F1/F2/F3：进度流 + 会话模式 + 证据摘要（2026-09-23）
# ----------------------------------------------------------------------
def test_set_mode_writes_session_file_and_rejects_unknown(server, tmp_path):
    r = _call(server, "tools/call",
              {"name": "pentest_set_mode", "arguments": {"mode": "ctf-web"}},
              msg_id=21)
    payload = json.loads(r["result"]["content"][0]["text"])
    assert payload["ok"] is True and payload["mode"] == "ctf-web"
    state = Path(server.data_dir) / "session-mode.json"
    assert state.exists() and json.loads(state.read_text(encoding="utf-8"))["mode"] == "ctf-web"

    r2 = _call(server, "tools/call",
               {"name": "pentest_set_mode", "arguments": {"mode": "ghost-mode"}},
               msg_id=22)
    assert r2["result"]["isError"] is True
    # 拒绝不覆盖已写入的值
    assert json.loads(state.read_text(encoding="utf-8"))["mode"] == "ctf-web"

    r3 = _call(server, "tools/call",
               {"name": "pentest_set_mode", "arguments": {}}, msg_id=23)
    payload3 = json.loads(r3["result"]["content"][0]["text"])
    assert payload3["mode"] == "ctf-web" and payload3["source"] == "会话"


def test_agent_resolves_session_mode_with_correct_priority(tmp_path):
    from penagent.mcp import PentestMCPServer

    # 会话文件 > 服务端默认；显式参数 > 会话文件
    srv = PentestMCPServer(data_dir=str(tmp_path / "data"),
                           default_mode="pentest-standard")
    (Path(srv.data_dir) / "session-mode.json").write_text(
        json.dumps({"mode": "ctf-web"}), encoding="utf-8")
    assert srv._agent().mode.id == "ctf-web"
    assert srv._agent(mode_id="ctf-crypto").mode.id == "ctf-crypto"

    # 文件缺失/损坏时回落服务端默认（fail-open）
    (Path(srv.data_dir) / "session-mode.json").write_text("{broken", encoding="utf-8")
    assert srv._agent().mode.id == "pentest-standard"


def test_progress_notifications_emitted(server, monkeypatch):
    """tools/call 带 _meta.progressToken 时，任务事件转成 notifications/progress。"""
    captured = []

    class _FakeAgent:
        def __init__(self, on_event):
            self.on_event = on_event

        def run(self, target, objective):
            self.on_event({"type": "mission_start", "mission": "m1"})
            self.on_event({"type": "step", "step": 1, "tool": "port_scan", "ok": True})
            self.on_event({"type": "done", "mission": "m1", "outcome": "success"})

            class _R:
                outcome = "success"

                def to_dict(self):
                    return {"outcome": "success", "steps": 1}
            return _R()

    monkeypatch.setattr(
        type(server), "_agent",
        lambda self, authorize=False, mode_id="", on_event=None: _FakeAgent(on_event))
    monkeypatch.setattr(server, "_notify",
                        lambda method, params: captured.append((method, params)))

    r = _call(server, "tools/call",
              {"name": "pentest_run",
               "arguments": {"target": "http://x", "objective": "t"},
               "_meta": {"progressToken": "tok-1"}}, msg_id=31)
    assert r["result"]["isError"] is False
    progress = [p for m, p in captured if m == "notifications/progress"]
    assert len(progress) == 3
    assert all(p["progressToken"] == "tok-1" for p in progress)
    assert "port_scan" in progress[1]["message"]


def test_no_progress_token_no_notifications(server, monkeypatch):
    """未带进度令牌：不发任何进度通知（静默降级）。"""
    captured = []

    class _FakeAgent:
        def __init__(self, on_event):
            self.on_event = on_event

        def run(self, target, objective):
            assert self.on_event is None  # 无令牌 → 不注入回调

            class _R:
                outcome = "success"

                def to_dict(self):
                    return {"outcome": "success"}
            return _R()

    monkeypatch.setattr(
        type(server), "_agent",
        lambda self, authorize=False, mode_id="", on_event=None: _FakeAgent(on_event))
    monkeypatch.setattr(server, "_notify",
                        lambda method, params: captured.append(method))
    _call(server, "tools/call",
          {"name": "pentest_run",
           "arguments": {"target": "http://x", "objective": "t"}}, msg_id=32)
    assert captured == []


def test_evidence_tool_returns_summary(server):
    r = _call(server, "tools/call",
              {"name": "pentest_evidence", "arguments": {}}, msg_id=41)
    text = r["result"]["content"][0]["text"]
    assert "证据链" in text
