"""可插拔成功判定器测试。

覆盖：
- flag 命中即收口 / 未命中在 auto_retry 内重试后命中 / 重试耗尽判失败
- 渗透模式引用伪造证据仍被拦（反幻觉底线，任何判定器都不可绕过）
- 判定器由模式挂载（pentest-standard -> evidence_chain，ctf-web -> flag_regex）
- 不传模式时沿用升级前的证据链语义（向后兼容）
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.memory import Memory
from penagent.modes import load_mode
from penagent.tools import ToolRegistry, ToolSpec
from penagent.verifier import (EvidenceChainVerifier, FlagRegexVerifier,
                               build_verifier)

FLAG = r"(?i)(flag|ctf)\{[^}]+\}"


def _evidence(tmp_path, texts=()):
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    for text in texts:
        ev.append("tool_call", {"tool": "http_get", "output": text})
    return ev


def _agent(tmp_path, mode=None, *, authorize=True, max_steps=6):
    reg = ToolRegistry()
    reg.register(ToolSpec(name="http_get", description="取回目标页面",
                          parameters={"url": {"type": "string"}}))
    return PenAgent(reg, Memory(tmp_path / "mem"),
                    EvidenceChain(tmp_path / "chain.jsonl"), LLMConfig(),
                    policy=Policy(allowed_targets=["127.0.0.1"],
                                  authorize=authorize),
                    max_steps=max_steps, mode=mode)


def _mock_llm(monkeypatch, decisions):
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))


# ----------------------------------------------------------------------
# 1. flag 命中
# ----------------------------------------------------------------------
def test_flag_regex_hit(tmp_path):
    verifier = FlagRegexVerifier(pattern=FLAG, auto_retry=3)
    result = verifier.verify({"summary": "拿到了 flag{abc-123}"},
                             _evidence(tmp_path))
    assert result.ok
    assert "flag{abc-123}" in result.reason


def test_flag_hit_ends_ctf_mission(monkeypatch, tmp_path):
    _mock_llm(monkeypatch, [
        {"thought": "读取页面", "tool": "http_get",
         "args": {"url": "http://127.0.0.1"}},
        {"thought": "拿到", "done": True, "summary": "flag{ctf-1}"},
    ])
    agent = _agent(tmp_path, load_mode("ctf-web"))
    result = agent.run("http://127.0.0.1", "解题")
    assert result.outcome == "success" and "flag{ctf-1}" in result.summary


def test_flag_matched_from_tool_output(tmp_path):
    """flag 出现在任务期间的工具输出里（模型总结未复述）也算命中。"""
    verifier = FlagRegexVerifier(pattern=FLAG, auto_retry=0)
    evidence = _evidence(tmp_path, ["<html>here: ctf{from-output}</html>"])
    result = verifier.verify({"summary": "页面已取回"}, evidence,
                             context="<html>here: ctf{from-output}</html>")
    assert result.ok and "ctf{from-output}" in result.reason


# ----------------------------------------------------------------------
# 2. 未命中 -> 重试 -> 命中
# ----------------------------------------------------------------------
def test_flag_miss_then_hit_within_retry(tmp_path):
    verifier = FlagRegexVerifier(pattern=FLAG, auto_retry=2)
    first = verifier.verify({"summary": "还没找到"}, _evidence(tmp_path))
    assert not first.ok and first.retryable and "剩余重试" in first.reason

    second = verifier.verify({"summary": "flag{retry-ok}"}, _evidence(tmp_path))
    assert second.ok and verifier.attempts == 2


def test_flag_retry_then_hit_in_mission(monkeypatch, tmp_path):
    """主循环把判定未过的原因回灌，模型下一次收口命中 flag。"""
    _mock_llm(monkeypatch, [
        {"thought": "先收口试试", "done": True, "summary": "尚未找到 flag"},
        {"thought": "再试一次", "done": True, "summary": "flag{second-try}"},
    ])
    agent = _agent(tmp_path, load_mode("ctf-web"))
    result = agent.run("http://127.0.0.1", "解题")
    assert result.outcome == "success"
    assert result.steps == 2                     # 第一次收口被判定未过
    assert "flag{second-try}" in result.summary


# ----------------------------------------------------------------------
# 3. 重试耗尽判失败
# ----------------------------------------------------------------------
def test_flag_retry_exhausted(tmp_path):
    verifier = FlagRegexVerifier(pattern=FLAG, auto_retry=1)
    assert verifier.verify({"summary": "无"}, _evidence(tmp_path)).retryable
    exhausted = verifier.verify({"summary": "仍无"}, _evidence(tmp_path))
    assert not exhausted.ok and not exhausted.retryable
    assert "重试已耗尽" in exhausted.reason


def test_flag_mission_fails_when_retries_exhausted(monkeypatch, tmp_path):
    """ctf-web 的 auto_retry=3：连续 4 次收口未命中即判失败。"""
    _mock_llm(monkeypatch, [
        {"thought": "收口", "done": True, "summary": "没有 flag"},
    ] * 4)
    agent = _agent(tmp_path, load_mode("ctf-web"))
    result = agent.run("http://127.0.0.1", "解题")
    assert result.outcome == "failed"
    assert "重试已耗尽" in result.summary
    assert result.steps == 4


# ----------------------------------------------------------------------
# 4. 反幻觉底线：伪造证据引用一律判失败，且不给重试
# ----------------------------------------------------------------------
def test_forged_evidence_blocked_in_pentest_mode(monkeypatch, tmp_path):
    _mock_llm(monkeypatch, [
        {"thought": "编造结论", "done": True, "summary": "存在漏洞",
         "evidence_refs": [99]},
    ])
    agent = _agent(tmp_path, load_mode("pentest-standard"))
    result = agent.run("http://127.0.0.1", "侦察")
    assert result.outcome == "failed"
    assert "反幻觉" in result.summary


def test_forged_evidence_not_retryable_even_with_auto_retry(tmp_path):
    """CTF 模式允许重试，但伪造证据不在此列（硬规则 2 是内核底线）。"""
    verifier = FlagRegexVerifier(pattern=FLAG, auto_retry=3)
    result = verifier.verify({"summary": "flag{fake}", "evidence_refs": [42]},
                             _evidence(tmp_path))
    assert not result.ok and not result.retryable
    assert "反幻觉" in result.reason


def test_evidence_chain_verifier_wraps_valid_refs(tmp_path):
    """包装后的引用校验与 evidence.valid_refs 语义一致。"""
    evidence = _evidence(tmp_path, ["a", "b"])
    verifier = EvidenceChainVerifier()
    ok = verifier.verify({"summary": "结论", "evidence_refs": [1, 2]}, evidence)
    assert ok.ok and ok.evidence_refs == (1, 2)

    verifier.reset()
    bad = verifier.verify({"summary": "结论", "evidence_refs": [1, 3]}, evidence)
    assert not bad.ok and "1 条不存在的证据" in bad.reason


# ----------------------------------------------------------------------
# 5. 模式挂载与向后兼容
# ----------------------------------------------------------------------
def test_verifier_wired_from_mode(tmp_path):
    pentest = _agent(tmp_path / "p", load_mode("pentest-standard"))
    assert isinstance(pentest.verifier, EvidenceChainVerifier)
    assert pentest.verifier.require_poc is True

    ctf = _agent(tmp_path / "c", load_mode("ctf-web"))
    assert isinstance(ctf.verifier, FlagRegexVerifier)
    assert ctf.verifier.auto_retry == 3
    assert ctf.verifier.pattern == load_mode("ctf-web").verifier.pattern


def test_require_poc_rejects_conclusion_without_refs(monkeypatch, tmp_path):
    """pentest-standard 声明 require_poc：结论必须带可复现证据引用。"""
    _mock_llm(monkeypatch, [
        {"thought": "直接收口", "done": True, "summary": "没找到问题"},
    ])
    agent = _agent(tmp_path, load_mode("pentest-standard"))
    result = agent.run("http://127.0.0.1", "侦察")
    assert result.outcome == "failed"
    assert "require_poc" in result.summary


def test_backward_compatible_without_mode(monkeypatch, tmp_path):
    """不传模式：结论无需 PoC 引用（与升级前一致），伪造引用仍被拦。"""
    agent = _agent(tmp_path, None)
    assert isinstance(agent.verifier, EvidenceChainVerifier)
    assert agent.verifier.require_poc is False

    _mock_llm(monkeypatch, [
        {"thought": "收口", "done": True, "summary": "ok"},
    ])
    assert agent.run("http://127.0.0.1", "侦察").outcome == "success"

    forged = _agent(tmp_path / "forged", None)
    _mock_llm(monkeypatch, [
        {"thought": "编造", "done": True, "summary": "ok", "evidence_refs": [7]},
    ])
    result = forged.run("http://127.0.0.1", "侦察")
    assert result.outcome == "failed" and "反幻觉" in result.summary


def test_build_verifier_rejects_flag_regex_without_pattern():
    class Spec:
        type = "flag_regex"
        pattern = None
        auto_retry = 0
        require_poc = False

    with pytest.raises(ValueError):
        build_verifier(Spec())
