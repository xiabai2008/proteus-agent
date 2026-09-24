"""核心模块测试：证据链 / 记忆 / 工具注册表 / 内置工具。"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.builtin_tools import register_builtins
from penagent.evidence import EvidenceChain
from penagent.memory import Memory, Skill
from penagent.tools import ToolRegistry, ToolSpec


# ----------------------------------------------------------------------
def test_evidence_chain_hash_link(tmp_path):
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    r1 = ev.append("decision", {"step": 1})
    r2 = ev.append("tool_call", {"tool": "port_scan"})
    assert r1.seq == 1 and r2.seq == 2
    assert r2.prev_hash == r1.hash
    assert ev.verify()["ok"]
    assert len(ev.load()) == 2


def test_evidence_tamper_detected(tmp_path):
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    ev.append("decision", {"step": 1})
    ev.append("tool_call", {"tool": "http_probe"})
    # 篡改第一条
    lines = (tmp_path / "chain.jsonl").read_text(encoding="utf-8").splitlines()
    import json

    d = json.loads(lines[0])
    d["content"]["step"] = 99
    (tmp_path / "chain.jsonl").write_text(
        "\n".join([json.dumps(d, ensure_ascii=False)] + lines[1:]),
        encoding="utf-8")
    v = ev.verify()
    assert not v["ok"]
    assert 1 in v["tampered"]
    assert 2 in v["broken_links"]


def test_evidence_valid_refs(tmp_path):
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    ev.append("decision", {"step": 1})
    assert ev.valid_refs([1, 99]) == [1]
    assert len(ev.refs([1])) == 1


# ----------------------------------------------------------------------
def test_memory_mission_lifecycle(tmp_path):
    m = Memory(tmp_path)
    mid = m.new_mission("http://127.0.0.1:8080", "侦察")
    m.add_step(mid, {"step": 1, "tool": "port_scan"})
    m.finish(mid, "success", "反思内容")
    rec = m.get_mission(mid)
    assert rec["outcome"] == "success"
    assert len(rec["steps"]) == 1
    assert rec["reflection"] == "反思内容"
    assert len(m.list_missions()) == 1


def test_memory_skills(tmp_path):
    m = Memory(tmp_path)
    m.add_skill(Skill(id="s1", title="侦察", target_fingerprint="flask"))
    assert len(m.list_skills()) == 1
    assert m.find_skills("python flask web") == [m.list_skills()[0]]
    assert m.find_skills("java spring") == []


# ----------------------------------------------------------------------
def test_builtin_tools_registry():
    reg = ToolRegistry()
    register_builtins(reg)
    assert {"port_scan", "http_probe", "dns_lookup", "robots_fetch"} \
        <= set(reg.names())
    schemas = reg.schemas()
    assert all("name" in s and "description" in s for s in schemas)


def test_builtin_tools_execute():
    reg = ToolRegistry()
    register_builtins(reg)
    r = reg.execute("dns_lookup", {"domain": "localhost"})
    assert r.ok and "127.0.0.1" in r.output["ips"]


def test_unknown_tool():
    reg = ToolRegistry()
    r = reg.execute("ghost", {})
    assert not r.ok and "未知工具" in r.error


def test_cli_tool_missing_binary(tmp_path):
    reg = ToolRegistry()
    reg.register(ToolSpec(name="ghost_tool", kind="cli",
                          command=["definitely-not-exist-xyz", "{args}"]))
    r = reg.execute("ghost_tool", {"target": "x"})
    assert not r.ok
    assert "不可用" in r.error


def test_cli_args_expansion():
    from penagent.tools import ToolRegistry as TR

    assert TR._cli_args(None, {"target": "http://x", "verbose": True}) == [
        "--target", "http://x", "--verbose"]


# ----------------------------------------------------------------------
# 工具结果语义（2026-09-24 实测修复）
#
# 判据：**抛异常、或返回值带非空 `error` 键 = ok=False**。
# 此前只按"是否抛异常"判失败，而 function 型工具用「返回 {"error": ...}」
# 表达业务失败 → 失败被记成成功：证据链/作战记录/gaps 统计/评测评分卡全按
# ok 读，MCP 层再给出 isError=false，DSH 会话里的外层模型看到"成功"不会改
# 策略（实测重复了 57 次同一个失败调用，60 步预算耗尽）。
# ----------------------------------------------------------------------
def _error_dict_tool() -> ToolSpec:
    return ToolSpec(name="fake_lookup", description="返回 error 字典",
                    parameters={"key": {"type": "string"}},
                    fn=lambda **kw: {"key": kw.get("key"), "error": "没找到"})


def test_dict_error_maps_to_not_ok():
    reg = ToolRegistry()
    reg.register(_error_dict_tool())

    r = reg.execute("fake_lookup", {"key": "x"})
    assert not r.ok
    assert r.error == "没找到"
    # output 原样保留：错误正文仍要能被模型读到并自我纠正
    assert r.output == {"key": "x", "error": "没找到"}
    assert r.to_dict()["ok"] is False


def test_ok_kept_for_empty_error_and_non_dict_output():
    reg = ToolRegistry()
    reg.register(ToolSpec(name="placeholder", parameters={},
                          fn=lambda **kw: {"error": "", "v": 1}))
    reg.register(ToolSpec(name="plain", parameters={},
                          fn=lambda **kw: "纯文本输出"))
    assert reg.execute("placeholder", {}).ok
    assert reg.execute("plain", {}).ok


def test_real_tools_report_failure_as_not_ok(tmp_path):
    """真实工具契约：文件不存在 / 解码方式不支持 / HTTP 方法不支持 → 失败。"""
    from penagent.builtin_tools import http_raw
    from penagent.ctf_tools import codec_chain, file_type

    reg = ToolRegistry()
    reg.register(ToolSpec(name="file_type", fn=file_type,
                          parameters={"path": {"type": "string"}}))
    reg.register(ToolSpec(name="codec_chain", fn=codec_chain,
                          parameters={"data": {"type": "string"},
                                      "codecs": {"type": "string"}}))
    reg.register(ToolSpec(name="http_raw", fn=http_raw,
                          parameters={"url": {"type": "string"},
                                      "method": {"type": "string"}}))

    missing = reg.execute("file_type", {"path": str(tmp_path / "nope.txt")})
    assert not missing.ok and "文件不存在" in missing.error

    bad_codec = reg.execute("codec_chain", {"data": "abc", "codecs": "nope"})
    assert not bad_codec.ok and "不支持的解码方式" in bad_codec.error

    bad_method = reg.execute("http_raw", {"url": "http://127.0.0.1/",
                                          "method": "TRACE"})
    assert not bad_method.ok and "不支持的方法" in bad_method.error
