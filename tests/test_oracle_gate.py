"""P0-1：flag 结论的判定器接受性（oracle gate）——标注"未验证"但不判失败。

2026-09-27 拍板：flag 正则只证明"格式像 flag"，证明不了"题目自带 checker 接受
它"（实测里模型交的正则命中、真机 ret=0）。因此命中后再查证据链里有没有
`native_emu` 的 accept 留证：有 → 标"判定器已接受"；没有 → 标"未验证"。
**未验证不判失败**（不改判定口径），但任务记录与报告都带出来，报告/评分卡据此
区分"解出"与"自称解出"。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.builtin_tools import report_gen
from penagent.evidence import EvidenceChain
from penagent.memory import Memory
from penagent.modes import load_mode
from penagent.tools import ToolRegistry, ToolSpec
from penagent.verifier import (FlagRegexVerifier, flags_in_text,
                               oracle_accepts, oracle_evidence, oracle_facts)

FLAG = "flag{9c668242-d497-2980-aae3-61c3f64f556a}"
OTHER = "flag{f35b8ad6-2c51-4a85-93c0-0e6279347b1a}"
PATTERN = r"(?i)(flag|ctf)\{[^}]+\}"


# ----------------------------------------------------------------------
# 1. 工具执行层留证
# ----------------------------------------------------------------------
def test_oracle_evidence_extracts_flags_from_args_and_output():
    """flag 候选从参数与输出里捞——accept 针对的 flag 通常在参数里。"""
    fields = oracle_evidence("native_emu",
                             {"verdict": "accept", "ret": 1},
                             {"args": f"str:{FLAG},len"})
    assert fields["oracle"] == "accept"
    assert fields["flags"] == [FLAG]


def test_oracle_evidence_skips_non_oracle_tools():
    """非判定器工具只留 flag 候选，不产生 oracle 结论。"""
    fields = oracle_evidence("python_solve", f"candidate flag: {FLAG}",
                             {"code": "print(1)"})
    assert fields == {"flags": [FLAG]}


def test_oracle_evidence_reads_string_output():
    """工具输出是字符串（MCP 路径）时也能读出 verdict。"""
    assert oracle_evidence("native_emu", '{"verdict": "reject"}')["oracle"] \
        == "reject"


def test_flags_in_text_is_deduped_and_limited():
    text = f"{FLAG} {FLAG} {OTHER} flag{{c}} flag{{d}} flag{{e}} flag{{f}}"
    assert flags_in_text(text, limit=3) == [FLAG, OTHER, "flag{c}"]


# ----------------------------------------------------------------------
# 2. 接受性核对（按任务隔离）
# ----------------------------------------------------------------------
def test_oracle_accepts_needs_accept_record_with_same_flag(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "m1", "tool": "python_solve",
                               "flags": [FLAG]})
    chain.append("tool_call", {"mission": "m1", "tool": "native_emu",
                               "oracle": "accept", "flags": [OTHER]})
    assert not oracle_accepts(FLAG, chain, mission="m1")   # 别的 flag 的接受不算
    assert oracle_accepts(OTHER, chain, mission="m1")


def test_oracle_accepts_is_mission_scoped(tmp_path):
    """上一单任务的 accept 不能替下一单背书。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "m1", "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})
    assert oracle_accepts(FLAG, chain, mission="m1")
    assert not oracle_accepts(FLAG, chain, mission="m2")


# ----------------------------------------------------------------------
# 3. 判定器：命中但未验证 → 仍判成功，只标注
# ----------------------------------------------------------------------
def _verify(tmp_path, mission="m1", with_accept=False):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    if with_accept:
        chain.append("tool_call", {"mission": mission, "tool": "native_emu",
                                   "oracle": "accept", "flags": [FLAG]})
    verifier = FlagRegexVerifier(pattern=PATTERN, auto_retry=3)
    decision = {"summary": f"拿到 {FLAG}", "evidence_refs": []}
    return verifier.verify(decision, chain, context="", mission=mission)


def test_flag_verifier_annotates_unverified_without_failing(tmp_path):
    result = _verify(tmp_path, with_accept=False)
    assert result.ok is True                 # 拍板：未验证不判失败
    assert result.flag_verified is False
    assert "未验证" in result.reason and FLAG in result.reason


def test_flag_verifier_marks_accepted(tmp_path):
    result = _verify(tmp_path, with_accept=True)
    assert result.ok is True and result.flag_verified is True
    assert "判定器已接受" in result.reason


def test_flag_verifier_accept_from_other_mission_does_not_count(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "m1", "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})
    verifier = FlagRegexVerifier(pattern=PATTERN, auto_retry=3)
    result = verifier.verify({"summary": FLAG, "evidence_refs": []}, chain,
                             mission="m2")
    assert result.flag_verified is False


def test_flag_verifier_without_match_still_retries(tmp_path):
    """未命中格式的行为不变（可重试语义没有被本次改动影响）。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    verifier = FlagRegexVerifier(pattern=PATTERN, auto_retry=1)
    result = verifier.verify({"summary": "还没找到", "evidence_refs": []}, chain)
    assert result.ok is False and result.retryable is True
    assert result.flag_verified is None


# ----------------------------------------------------------------------
# 4. 报告事实（宿主路径的机检口径）
# ----------------------------------------------------------------------
def test_report_gen_exposes_flag_verified_and_unverified_note(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "m1", "tool": "python_solve",
                               "flags": [FLAG]})          # 出现过，未验证
    out = report_gen(mission_id="m1", data_dir=str(tmp_path))
    assert out["ok"] is True
    assert out["flag_verified"] is False
    assert out["flags_seen"] == [FLAG] and out["flags_accepted"] == []
    assert "未验证" in out["note"] and FLAG in out["note"]

    chain.append("tool_call", {"mission": "m1", "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})
    out2 = report_gen(mission_id="m1", data_dir=str(tmp_path))
    assert out2["flag_verified"] is True
    assert out2["flags_accepted"] == [FLAG]
    assert "note" not in out2


def test_oracle_facts_sorted_by_mission(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "m1", "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})
    assert oracle_facts(chain, "m1")["flag_verified"] is True
    assert oracle_facts(chain, "m2") == {"flags_seen": [], "flags_accepted": [],
                                         "flag_verified": False}


# ----------------------------------------------------------------------
# 5. 主循环端到端：任务记录带 flag_verified（stub 判定器工具）
# ----------------------------------------------------------------------
def _ctf_agent(monkeypatch, tmp_path, decisions, tool_output):
    """ctf-crypto 模式 + stub native_emu（不依赖 unicorn/真实 ELF）。"""
    registry = ToolRegistry()
    registry.register(ToolSpec(
        name="native_emu", description="stub",
        parameters={"elf": {"type": "string"}, "args": {"type": "string"}},
        fn=lambda **kwargs: tool_output))
    memory = Memory(tmp_path / "mem")
    evidence = EvidenceChain(tmp_path / "chain.jsonl")
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda config, messages, **kw: decisions.pop(0))
    mode = load_mode("ctf-crypto")
    return PenAgent(registry, memory, evidence,
                    policy=Policy(allowed_targets=["127.0.0.1"],
                                  authorize=True, mode=mode),
                    mode=mode, max_steps=6)


def test_loop_records_unverified_flag(monkeypatch, tmp_path):
    """判定器没被调用过 → 任务成功但 flag_verified=False（标注，不判失败）。"""
    decisions = [
        {"thought": "直接报答案", "done": True,
         "summary": f"flag 是 {FLAG}", "evidence_refs": [1]},
    ]
    agent = _ctf_agent(monkeypatch, tmp_path, decisions, {"verdict": "reject"})
    result = agent.run("题面", "解出 flag")

    assert result.outcome == "success"
    assert result.flag_verified is False
    record = agent.memory.get_mission(result.mission_id)
    assert record["flag_verified"] is False
    conclusion = [r for r in agent.evidence.load()
                  if r.kind == "conclusion"][-1]
    assert conclusion.content["flag_verified"] is False


def test_loop_records_accepted_flag(monkeypatch, tmp_path):
    """判定器返回 accept（flag 在参数里）→ flag_verified=True。"""
    decisions = [
        {"thought": "先跑判定器", "tool": "native_emu",
         "args": {"elf": "checker.so", "args": f"str:{FLAG},len"}},
        {"thought": "判定器接受了", "done": True,
         "summary": f"flag 是 {FLAG}", "evidence_refs": [1, 2]},
    ]
    agent = _ctf_agent(monkeypatch, tmp_path, decisions,
                       {"verdict": "accept", "ret": 1})
    result = agent.run("题面", "解出 flag")
    assert result.outcome == "success"
    assert result.flag_verified is True
    assert agent.memory.get_mission(result.mission_id)["flag_verified"] is True


# ----------------------------------------------------------------------
# 6. flag_claim（P2-1）：把"声明"变成一条可查的记录
# ----------------------------------------------------------------------
def test_flag_claim_verifies_against_chain(tmp_path):
    """有 accept 留证（同任务）→ verified=True，声明入链 + 入作战记录。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "m1", "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})
    from penagent.flag_claim import flag_claim

    out = flag_claim(flag=FLAG, mission_id="m1", data_dir=str(tmp_path))
    assert out["ok"] is True and out["verified"] is True
    assert "已接受" in out["reason"] and out["record_seq"] > 0

    conclusions = [r for r in chain.load() if r.kind == "conclusion"]
    assert conclusions[-1].content["flag"] == FLAG
    assert conclusions[-1].content["flag_verified"] is True
    assert conclusions[-1].content["source"] == "flag_claim"


def test_flag_claim_unverified_is_annotated_not_failed(tmp_path):
    """没有 accept → verified=False + 补跑判定器的提示；记录照写（只标注）。"""
    from penagent.flag_claim import flag_claim

    out = flag_claim(flag=FLAG, mission_id="m1", data_dir=str(tmp_path))
    assert out["ok"] is True and out["verified"] is False
    assert "未验证" in out["reason"] and "native_emu" in out["hint"]

    from penagent.memory import Memory

    memory = Memory(tmp_path)
    mission_id = memory.new_mission("题面", "解出 flag")
    out2 = flag_claim(flag=FLAG, mission_id=mission_id, data_dir=str(tmp_path))
    assert out2["verified"] is False
    rec = memory.get_mission(mission_id)
    assert rec["flag_claims"] == [{"flag": FLAG, "verified": False}]
    assert "flag_verified" not in rec          # 没验证过 ≠ 验证失败


def test_flag_claim_marks_mission_verified_only_when_accepted(tmp_path):
    """真被接受过才写 flag_verified=True（评分卡据此算假声明率）。"""
    from penagent.flag_claim import flag_claim
    from penagent.memory import Memory

    memory = Memory(tmp_path)
    mission_id = memory.new_mission("题面", "解出 flag")
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": mission_id, "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})

    assert flag_claim(flag=FLAG, mission_id=mission_id,
                      data_dir=str(tmp_path))["verified"] is True
    assert memory.get_mission(mission_id)["flag_verified"] is True


def test_flag_claim_rejects_non_flag_shape(tmp_path):
    from penagent.flag_claim import flag_claim

    bad = flag_claim(flag="not-a-flag", data_dir=str(tmp_path))
    assert bad["ok"] is False and "不是 flag 形态" in bad["error"]
    assert "hint" in bad
    empty = flag_claim(data_dir=str(tmp_path))
    assert empty["ok"] is False and "缺少 flag" in empty["error"]


def test_flag_claim_without_mission_checks_whole_chain(tmp_path):
    """未绑定任务时按全链核对，并在理由里标注这一点。"""
    from penagent.flag_claim import flag_claim

    chain = EvidenceChain(tmp_path / "chain.jsonl")
    chain.append("tool_call", {"mission": "other", "tool": "native_emu",
                               "oracle": "accept", "flags": [FLAG]})
    out = flag_claim(flag=FLAG, data_dir=str(tmp_path))
    assert out["verified"] is True
    assert "未绑定任务" in out["reason"] and "mission" not in out


def test_flag_claim_registered_in_ctf_modes_only():
    from penagent.modes import load_mode
    from penagent.registry import build_center

    center = build_center()
    for mode_id in ("ctf-web", "ctf-crypto", "ctf-reverse"):
        entries = {e.name: e for e in center.discover(mode_id=mode_id)}
        assert "flag_claim" in entries, mode_id
        assert set(entries["flag_claim"].modes) == {"ctf-web", "ctf-crypto",
                                                    "ctf-reverse"}
        assert "flag_claim" in load_mode(mode_id).capability.allow
    pentest = center.build_registry(load_mode("pentest-standard"))
    assert "flag_claim" not in pentest.names()
