"""§8.7-2 mission 自动绑定回归：底层直调也要进作战记录。

历史缺陷（2026-09-26 attach 矩阵实测）：DSH 会话里 agent 几乎不走
pentest_run，直接调 `mcp__proteus__http_raw` 等底层工具——
`pentest_missions` 全程 0 条调用，`report_gen` 产出薄报告（agent 自评
"report is thin (no mission bound)"）。修复：MCP 入口对底层直调自动
建任务 + 每调用留证 + report_gen 自动带 mission_id。
"""
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


def _payload(response) -> object:
    blocks = response["result"]["content"]
    assert isinstance(blocks, list) and blocks[0]["type"] == "text"
    return json.loads(blocks[0]["text"])


def test_direct_call_creates_bound_mission(server):
    """首个底层直调自动建任务：target 从参数提取、分区落在 default。"""
    _call(server, "tools/call",
          {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
          msg_id=2)
    missions = _payload(_call(server, "tools/call",
                              {"name": "pentest_missions"}, msg_id=3))
    assert len(missions) == 1
    assert missions[0]["target"] == "localhost"
    assert "dns_lookup" in missions[0]["objective"]
    assert missions[0]["outcome"] == "running"


def test_direct_calls_append_steps(server):
    """后续每次直调都挂到绑定任务上：步数累计、链上有 direct 记录。

    目标端点不同（localhost 无端口 vs localhost:1）视为目标切换——
    端点身份含端口（8090 与 8099 是不同的靶，不能混进一条任务）。
    """
    _call(server, "tools/call",
          {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
          msg_id=2)
    _call(server, "tools/call",
          {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
          msg_id=3)
    _call(server, "tools/call",
          {"name": "http_probe", "arguments": {"url": "http://localhost:1"}},
          msg_id=4)
    missions = _payload(_call(server, "tools/call",
                              {"name": "pentest_missions"}, msg_id=5))
    by_target = {m["target"]: m for m in missions}
    assert set(by_target) == {"localhost", "localhost:1"}
    first = by_target["localhost"]
    assert [s["tool"] for s in first["steps"]] == ["dns_lookup", "dns_lookup"]
    assert first["outcome"] == "completed"       # 目标切换时旧任务收口
    # 链上留证：每步有 evidence_seq 且能对上
    seqs = [s["evidence_seq"] for s in first["steps"]]
    assert all(isinstance(x, int) and x > 0 for x in seqs)


def test_report_gen_auto_binds_mission_id(server):
    """report_gen 不传 mission_id 时自动带绑定任务——报告含任务上下文。"""
    _call(server, "tools/call",
          {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
          msg_id=2)
    bound_id = server._bound_mission["id"]
    payload = _payload(_call(server, "tools/call", {
        "name": "report_gen", "arguments": {"format": "markdown"}}, msg_id=3))
    assert payload["ok"] is True
    assert bound_id in payload["output"]["report"]


def test_report_gen_explicit_mission_id_wins(server):
    """显式传了 mission_id 就不覆盖——自动注入只在缺省时兜底。"""
    _call(server, "tools/call",
          {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
          msg_id=2)
    payload = _payload(_call(server, "tools/call", {
        "name": "report_gen",
        "arguments": {"format": "markdown", "mission_id": "ghost0"}},
        msg_id=3))
    assert payload["ok"] is True
    report = payload["output"]["report"]
    # 关键断言：结果里没有绑定任务的 id（说明没被注入）
    assert server._bound_mission["id"] not in report


def test_extract_target_prefers_target_over_url():
    """target > url > base_url > host > domain；url 取 host。"""
    assert PentestMCPServer._extract_target(
        {"target": "10.0.0.1", "url": "http://a.b/c"}) == "10.0.0.1"
    assert PentestMCPServer._extract_target(
        {"url": "http://127.0.0.1:8090/pickle"}) == "127.0.0.1:8090"
    assert PentestMCPServer._extract_target({"domain": "example.com"}) == \
        "example.com"
    assert PentestMCPServer._extract_target({"body": "x"}) == ""


def test_target_backfilled_when_first_call_has_none(server):
    """首调不带目标信息（replay_request）时 target 为空，后续调用回填。"""
    _call(server, "tools/call",
          {"name": "replay_request", "arguments": {"request_id": "r1"}},
          msg_id=2)
    assert server._bound_mission["target"] == ""
    _call(server, "tools/call",
          {"name": "http_probe",
           "arguments": {"url": "http://127.0.0.1:8090/"}}, msg_id=3)
    assert server._bound_mission["target"] == "127.0.0.1:8090"
    missions = _payload(_call(server, "tools/call",
                              {"name": "pentest_missions"}, msg_id=4))
    assert missions[0]["target"] == "127.0.0.1:8090"


def test_target_switch_creates_new_mission(server):
    """内核进程跨会话复用：目标变了要收口旧任务、起新任务（2026-09-26
    矩阵实测：十个会话挤进一条 126 步任务——绑定是进程级的）。"""
    _call(server, "tools/call",
          {"name": "http_probe",
           "arguments": {"url": "http://127.0.0.1:8090/"}}, msg_id=2)
    first = server._bound_mission["id"]
    _call(server, "tools/call",
          {"name": "http_probe",
           "arguments": {"url": "http://127.0.0.1:8099/pickle"}}, msg_id=3)
    second = server._bound_mission["id"]
    assert second != first
    missions = _payload(_call(server, "tools/call",
                              {"name": "pentest_missions"}, msg_id=4))
    by_id = {m["id"]: m for m in missions}
    assert by_id[first]["outcome"] == "completed"      # 旧任务收口
    assert by_id[second]["target"] == "127.0.0.1:8099"
    assert by_id[first]["target"] == "127.0.0.1:8090"
    # 同目标重复调用不重绑
    _call(server, "tools/call",
          {"name": "http_probe",
           "arguments": {"url": "http://127.0.0.1:8099/note"}}, msg_id=5)
    assert server._bound_mission["id"] == second


def test_trace_fail_open_never_breaks_tool(server, monkeypatch):
    """留证任何一步炸掉都不影响工具结果（fail-open）。"""
    def boom(*a, **kw):
        raise RuntimeError("evidence broken")

    monkeypatch.setattr(server.evidence, "append", boom)
    r = _call(server, "tools/call",
              {"name": "dns_lookup", "arguments": {"domain": "localhost"}},
              msg_id=2)
    payload = _payload(r)
    assert "error" not in r
    assert payload["output"]["ips"]          # 工具本体照常返回
