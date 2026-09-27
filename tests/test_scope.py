"""会话授权目标测试（P0-4）。

覆盖三层：
- `penagent/scope.py` 的读写语义（含损坏文件回落）
- CLI `python -m penagent scope`（命令插件走的就是它）
- MCP 服务端集成：未授权目标被拒且错误信息带授权指引；人工授权后**立即**
  生效（无需重启内核）；越界目标不会因为授权文件而放宽基线
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent import scope
from penagent.cli import main
from penagent.mcp import PentestMCPServer


# ----------------------------------------------------------------------
# 1. scope.py：读写语义
# ----------------------------------------------------------------------
def test_scope_roundtrip(tmp_path):
    data = tmp_path / "data"
    assert scope.read_scope(data) == []                 # 缺失 → 空

    assert scope.add_targets(data, "example.com,10.0.0.5") == \
        ["example.com", "10.0.0.5"]
    assert scope.read_scope(data) == ["example.com", "10.0.0.5"]

    # 追加去重（重复项不产生第二条）
    assert scope.add_targets(data, "example.com, a.example.com") == \
        ["example.com", "10.0.0.5", "a.example.com"]

    assert scope.remove_targets(data, "10.0.0.5") == \
        ["example.com", "a.example.com"]
    assert scope.clear_scope(data) == []
    assert scope.read_scope(data) == []


def test_scope_tolerates_corrupt_file(tmp_path):
    """损坏/类型不对 → 空清单（不抛异常，也不静默放宽）。"""
    data = tmp_path / "data"
    data.mkdir()
    path = scope.scope_path(data)

    path.write_text("{ not json", encoding="utf-8")
    assert scope.read_scope(data) == []
    assert scope.read_reference(data) == []

    path.write_text(json.dumps(["a", "b"]), encoding="utf-8")   # 顶层不是对象
    assert scope.read_scope(data) == []

    path.write_text(json.dumps({"targets": "a,b"}), encoding="utf-8")
    assert scope.read_scope(data) == ["a", "b"]     # 字符串按逗号分隔（同 CLI）


# ----------------------------------------------------------------------
# 1b. 只读参考站（2026-09-27 实测新增）：公开 WP/知识库的读取通道
# ----------------------------------------------------------------------
def test_reference_roundtrip_and_isolation(tmp_path):
    """参考站与目标授权互不覆盖：动一类不能抹掉另一类。"""
    data = tmp_path / "data"
    scope.add_targets(data, "127.0.0.1")
    assert scope.add_reference(data, "xz.aliyun.com, ctf-wiki.org") == \
        ["xz.aliyun.com", "ctf-wiki.org"]
    assert scope.read_scope(data) == ["127.0.0.1"]        # 目标清单没被写坏

    scope.add_targets(data, "example.com")                # 再动目标
    assert scope.read_reference(data) == ["xz.aliyun.com", "ctf-wiki.org"]

    assert scope.remove_reference(data, "ctf-wiki.org") == ["xz.aliyun.com"]
    assert scope.read_scope(data) == ["127.0.0.1", "example.com"]

    scope.clear_scope(data)                               # clear 两类一起清
    assert scope.read_scope(data) == [] and scope.read_reference(data) == []


def test_read_only_classification():
    """放行判据是"读"：只读工具 + GET/HEAD；扫描器与写动作永远不算。"""
    assert scope.is_read_only_call("http_raw", {"url": "https://x/"}) is True
    assert scope.is_read_only_call("http_raw", {"method": "POST"}) is False
    assert scope.is_read_only_call("chameleon_scrape_url", {}) is True
    assert scope.is_read_only_call("chameleon_crawl_site", {}) is False
    assert scope.is_read_only_call("nuclei_scan", {}) is False
    assert scope.is_read_only_call("python_solve", {}) is False


def test_policy_allows_read_only_reference_but_not_attack(tmp_path):
    """参考站只开读取：GET 放行、POST 拒绝、扫描器拒绝、非参考站拒绝。"""
    from penagent.agent import Policy

    policy = Policy(allowed_targets=["127.0.0.1"],
                    reference_targets=["xz.aliyun.com"])
    spec = type("S", (), {"dangerous": False, "network": False})()

    ok, _ = policy.check("http_raw", spec,
                         {"url": "https://xz.aliyun.com/news/92577"})
    assert ok is True                                     # 只读读取放行

    ok, reason = policy.check("http_raw", spec,
                              {"url": "https://xz.aliyun.com/x",
                               "method": "POST"})
    assert ok is False and "add-ref" in reason            # 写动作不放行

    ok, reason = policy.check("nuclei_scan", spec,
                              {"target": "https://xz.aliyun.com"})
    assert ok is False and "不在授权范围" in reason        # 攻击面工具不放行

    ok, reason = policy.check("http_raw", spec,
                              {"url": "https://evil.example.com/"})
    assert ok is False                                    # 非参考站照旧拒绝
    assert "add-ref" in reason and "/proteus-scope add " in reason


def test_policy_reference_does_not_leak_to_subdomain_of_targets(tmp_path):
    """参考站匹配与目标匹配同一套规则（含子域），但不放宽 targets。"""
    from penagent.agent import Policy

    policy = Policy(allowed_targets=["127.0.0.1"],
                    reference_targets=["aliyun.com"])
    spec = type("S", (), {"dangerous": False, "network": False})()
    ok, _ = policy.check("http_raw", spec, {"url": "https://xz.aliyun.com/"})
    assert ok is True                                     # 子域命中参考站
    assert policy.allowed_targets == ["127.0.0.1"]        # 目标清单没被污染


def test_cli_add_ref_and_list(tmp_path, capsys):
    """CLI 入口：`scope --add-ref` 只动参考站名单。"""
    data = str(tmp_path / "data")
    assert main(["scope", "--data", data, "--add", "127.0.0.1"]) == 0
    capsys.readouterr()

    assert main(["scope", "--data", data,
                 "--add-ref", "xz.aliyun.com"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["reference"] == ["xz.aliyun.com"]
    assert payload["targets"] == ["127.0.0.1"]

    assert main(["scope", "--data", data]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["reference"] == ["xz.aliyun.com"]
    assert payload["targets"] == ["127.0.0.1"]


# ----------------------------------------------------------------------
# 2. CLI（命令插件与人工都走这条路）
# ----------------------------------------------------------------------
def test_cli_scope_add_list_remove(tmp_path, capsys):
    data = str(tmp_path / "data")

    assert main(["scope", "--add", "example.com", "--data", data]) == 0
    assert json.loads(capsys.readouterr().out)["targets"] == ["example.com"]

    assert main(["scope", "--data", data]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["targets"] == ["example.com"]
    assert listed["file"].endswith("session-scope.json")

    assert main(["scope", "--remove", "example.com", "--data", data]) == 0
    assert json.loads(capsys.readouterr().out)["targets"] == []

    assert main(["scope", "--add", "a.com", "--data", data]) == 0
    capsys.readouterr()
    assert main(["scope", "--clear", "--data", data]) == 0
    assert json.loads(capsys.readouterr().out)["targets"] == []


# ----------------------------------------------------------------------
# 3. MCP 服务端集成：授权前拒绝（带指引）→ 人工授权后立即生效
# ----------------------------------------------------------------------
def _call(server, method, params=None, msg_id=1):
    line = json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method,
                       "params": params or {}})
    return json.loads(server.handle_line(line))


def _payload(response) -> dict:
    return json.loads(response["result"]["content"][0]["text"])


def _dns(server, domain, msg_id=9):
    return _call(server, "tools/call",
                 {"name": "dns_lookup", "arguments": {"domain": domain}},
                 msg_id=msg_id)


def test_out_of_scope_denied_with_authorization_hint(tmp_path):
    server = PentestMCPServer(data_dir=str(tmp_path / "data"),
                              allowed_targets=["127.0.0.1"])
    r = _dns(server, "127.0.0.2")

    assert r["result"]["isError"] is True
    payload = _payload(r)
    assert "不在授权范围" in payload["error"]
    # 指引必须落在错误信息里：模型据此向人要授权，而不是自己想办法
    assert "/proteus-scope" in payload["error"]
    assert "模型不能自我授权" in payload["error"]


def test_session_scope_takes_effect_immediately(tmp_path):
    """人工授权后**下一次调用**即生效（内核逐请求重读，无需重启）。"""
    data = tmp_path / "data"
    server = PentestMCPServer(data_dir=str(data), allowed_targets=["127.0.0.1"])

    assert _dns(server, "127.0.0.2", msg_id=11)["result"]["isError"] is True

    scope.add_targets(data, "127.0.0.2", note="测试人工授权")
    r = _dns(server, "127.0.0.2", msg_id=12)
    assert r["result"]["isError"] is False
    assert "127.0.0.2" in _payload(r)["output"]["ips"]


def test_session_scope_extends_but_does_not_replace_baseline(tmp_path):
    """并集语义：授权新目标不会把基线（回环）挤掉。"""
    data = tmp_path / "data"
    server = PentestMCPServer(data_dir=str(data), allowed_targets=["127.0.0.1"])
    scope.add_targets(data, "example.com")

    assert _dns(server, "127.0.0.1", msg_id=13)["result"]["isError"] is False
    assert _dns(server, "example.com", msg_id=14)["result"]["isError"] is False
    # 未授权的仍然被拒
    assert _dns(server, "127.0.0.9", msg_id=15)["result"]["isError"] is True


def test_scope_change_refreshes_mode_tool_face(tmp_path):
    """授权变化会重建带模式工具面（否则缓存里还是旧白名单）。"""
    data = tmp_path / "data"
    server = PentestMCPServer(data_dir=str(data), allowed_targets=["127.0.0.1"],
                              default_mode="pentest-standard")
    assert "http_raw" in {t["name"] for t in _call(server, "tools/list")["result"]["tools"]}

    scope.add_targets(data, "example.com")
    assert _dns(server, "example.com", msg_id=16)["result"]["isError"] is False
