"""Agent 决策循环测试：安全护栏 / 反幻觉 / 决策流转（mock LLM）。"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.builtin_tools import register_builtins
from penagent.evidence import EvidenceChain
from penagent.memory import Memory
from penagent.tools import ToolRegistry


def _make(monkeypatch, decisions, targets=None, authorize=False,
          max_steps=5):
    import shutil

    reg = ToolRegistry()
    register_builtins(reg)
    tmp = Path(__file__).parent / "_tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    mem = Memory(tmp)
    ev = EvidenceChain(tmp / "chain.jsonl")

    def fake_chat_json(config, messages, **kw):
        return decisions.pop(0)

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)
    return PenAgent(reg, mem, ev,
                    policy=Policy(allowed_targets=targets or
                                  ["127.0.0.1"], authorize=authorize),
                    max_steps=max_steps)


def test_success_flow(monkeypatch):
    decisions = [
        {"thought": "先端口扫描", "tool": "port_scan",
         "args": {"host": "127.0.0.1", "ports": "8080"}},
        {"thought": "侦察完成", "done": True,
         "summary": "8080 开放",
         "evidence_refs": [1, 2]},
    ]
    agent = _make(monkeypatch, decisions)
    result = agent.run("http://127.0.0.1:8080", "侦察")
    assert result.outcome == "success"
    assert result.summary == "8080 开放"
    assert result.evidence_refs == [1, 2]
    # 证据链完整且结论引用真实证据
    assert agent.evidence.verify()["ok"]
    assert agent.evidence.valid_refs(result.evidence_refs) \
        == result.evidence_refs


def test_anti_hallucination_blocks_fake_refs(monkeypatch):
    """结论引用不存在的证据 -> 拒绝产出。"""
    decisions = [
        {"thought": "直接总结", "done": True, "summary": "x",
         "evidence_refs": [99]},   # 编造证据
    ]
    agent = _make(monkeypatch, decisions)
    result = agent.run("http://127.0.0.1:8080", "侦察")
    assert result.outcome == "failed"
    assert "反幻觉" in result.summary


def test_policy_blocks_out_of_scope_target(monkeypatch):
    """越权目标被护栏拦截。"""
    decisions = [
        {"thought": "扫描外部目标", "tool": "port_scan",
         "args": {"host": "192.168.1.1"}},
        {"thought": "换本地", "tool": "port_scan",
         "args": {"host": "127.0.0.1", "ports": "8080"}},
        {"thought": "完成", "done": True, "summary": "ok",
         "evidence_refs": []},
    ]
    agent = _make(monkeypatch, decisions)
    result = agent.run("http://127.0.0.1:8080", "侦察")
    assert result.outcome == "success"
    # 越权尝试被记录（护栏拦截日志）
    mission = agent.memory.get_mission(result.mission_id)
    blocked = [s for s in mission["steps"] if s.get("blocked")]
    assert len(blocked) == 1
    assert "授权范围" in blocked[0]["reason"]


def test_high_risk_requires_authorize(monkeypatch):
    """危险工具未授权 -> 护栏拦截。"""
    import shutil

    decisions = [
        {"thought": "全扫描", "tool": "rayscan_quick",
         "args": {"target": "http://127.0.0.1:8080"}},
        {"thought": "完成", "done": True, "summary": "ok",
         "evidence_refs": []},
    ]
    reg = ToolRegistry()
    register_builtins(reg)
    from penagent.tools import ToolSpec

    reg.register(ToolSpec(name="rayscan_quick", kind="cli",
                          description="危险扫描",
                          command=["python", "-V", "{args}"],
                          dangerous=True))
    tmp = Path(__file__).parent / "_tmp2"
    if tmp.exists():
        shutil.rmtree(tmp)
    mem = Memory(tmp)
    ev = EvidenceChain(tmp / "chain.jsonl")

    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))
    agent = PenAgent(reg, mem, ev, policy=Policy(authorize=False),
                     max_steps=3)
    result = agent.run("http://127.0.0.1:8080", "侦察")
    assert result.outcome == "success"
    mission = agent.memory.get_mission(result.mission_id)
    assert any(s.get("blocked") and "高危" in s["reason"]
               for s in mission["steps"])


def test_unknown_tool_feedback(monkeypatch):
    """LLM 选了不存在的工具 -> 反馈后继续。"""
    decisions = [
        {"thought": "错误工具", "tool": "no_such_tool", "args": {}},
        {"thought": "完成", "done": True, "summary": "ok",
         "evidence_refs": []},
    ]
    agent = _make(monkeypatch, decisions)
    result = agent.run("http://127.0.0.1:8080", "侦察")
    assert result.outcome == "success"


def test_max_steps_termination(monkeypatch):
    """步数耗尽终止。"""
    decisions = [
        {"thought": "循环", "tool": "dns_lookup", "args": {"domain": "x"}}
    ] * 10
    agent = _make(monkeypatch, decisions, max_steps=3)
    result = agent.run("http://127.0.0.1:8080", "侦察")
    assert result.outcome == "failed"
    assert "步数" in result.summary
