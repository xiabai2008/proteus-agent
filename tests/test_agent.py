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


# ----------------------------------------------------------------------
# 内核侧重复失败检测（R-39）：同工具 + 同参数连续失败到阈值 -> 拦截并回灌
# 纠正指令（宿主侧 supervisor 管的是会话层，CLI / MCP 的内核循环没有这道判据）
# ----------------------------------------------------------------------
def _loop_agent(tmp_path, plan, max_steps):
    """内核 + 一个结果按 `plan` 依次给出的 `flaky` 函数工具。

    plan 元素为 True（成功）/ False（业务失败：返回 {"error": ...}，
    经 business_error 映射为 ok=False）。
    """
    from penagent.tools import ToolSpec

    reg = ToolRegistry()
    calls = []

    def flaky(**kw):
        idx = len(calls)
        calls.append(kw)
        ok = plan[idx] if idx < len(plan) else plan[-1]
        return {"result": "ok"} if ok else {"error": "文件不存在: /tmp/x"}

    reg.register(ToolSpec(name="flaky", description="会失败的工具",
                          parameters={"path": {"type": "string"}}, fn=flaky))
    agent = PenAgent(reg, Memory(tmp_path / "mem"),
                     EvidenceChain(tmp_path / "chain.jsonl"),
                     policy=Policy(allowed_targets=["127.0.0.1"],
                                   authorize=True),
                     max_steps=max_steps)
    return agent, calls


def _mock_llm_capture(monkeypatch, decisions, seen):
    """桩 LLM：返回脚本化决策，并把每次请求的最后一条消息记进 seen。"""
    def fake_chat_json(config, messages, **kw):
        seen.append(messages[-1]["content"])
        return decisions.pop(0)

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)


def test_repeat_failure_blocks_next_same_call(monkeypatch, tmp_path):
    """连续 3 次同参失败后，第 4 次同调用被拦（不执行）并回灌纠正指令。"""
    agent, calls = _loop_agent(tmp_path, plan=[False] * 10, max_steps=5)
    seen = []
    _mock_llm_capture(monkeypatch, [
        {"thought": "试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "再试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "还试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "又试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "放弃", "done": True, "summary": "未完成",
         "evidence_refs": []},
    ], seen)
    result = agent.run("http://127.0.0.1", "重复失败")

    assert result.outcome == "success"          # 最后如实收口
    assert len(calls) == 3                      # 第 4 次同调用没有执行
    mission = agent.memory.get_mission(result.mission_id)
    blocked = [s for s in mission["steps"] if s.get("blocked")]
    assert len(blocked) == 1
    reason = blocked[0]["reason"]
    assert "连续失败 3 次" in reason             # 计数口径写进理由
    assert "文件不存在: /tmp/x" in reason        # 带上一次的真实失败原因
    assert "换思路" in reason
    assert blocked[0]["level"] == "loop"        # 与护栏拦截区分档位
    # 纠正指令确实回灌到了下一次决策（第 4 次拦截 -> 第 5 次决策前可见）
    assert "护栏拦截" in seen[4] and "连续失败 3 次" in seen[4]
    # 拦截入证据链：能回答"谁拦了什么"，且链仍完整
    evidence_blocked = [r for r in agent.evidence.load()
                        if r.kind == "tool_call" and r.content.get("blocked")]
    assert len(evidence_blocked) == 1
    assert evidence_blocked[0].content["level"] == "loop"
    assert agent.evidence.verify()["ok"]


def test_repeat_failure_counter_resets_on_success(monkeypatch, tmp_path):
    """同指纹成功一次即清零：之后重新累计，不误判为循环。"""
    agent, calls = _loop_agent(tmp_path,
                               plan=[False, False, True, False, False],
                               max_steps=6)
    seen = []
    _mock_llm_capture(monkeypatch, [
        {"thought": "试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "成功", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "再试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "再试", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "收口", "done": True, "summary": "ok", "evidence_refs": []},
    ], seen)
    result = agent.run("http://127.0.0.1", "失败后成功")

    assert result.outcome == "success"
    assert len(calls) == 5                      # 5 次全部执行，无一被拦
    mission = agent.memory.get_mission(result.mission_id)
    assert not [s for s in mission["steps"] if s.get("blocked")]


def test_repeat_failure_reset_by_changed_args(monkeypatch, tmp_path):
    """指纹 = 工具名 + 参数：换参数即换指纹，不被上一参数的计数牵连。"""
    agent, calls = _loop_agent(tmp_path, plan=[False] * 10, max_steps=6)
    seen = []
    same = {"path": "/tmp/x"}
    _mock_llm_capture(monkeypatch, [
        {"thought": "试", "tool": "flaky", "args": same},
        {"thought": "试", "tool": "flaky", "args": same},
        {"thought": "试", "tool": "flaky", "args": same},
        {"thought": "重复", "tool": "flaky", "args": same},
        {"thought": "换参数", "tool": "flaky", "args": {"path": "/tmp/y"}},
        {"thought": "收口", "done": True, "summary": "ok", "evidence_refs": []},
    ], seen)
    result = agent.run("http://127.0.0.1", "换参数")

    assert result.outcome == "success"
    # 前 3 次执行 + 第 5 步换参数后执行 = 4 次；第 4 步被拦
    assert len(calls) == 4
    assert calls[-1] == {"path": "/tmp/y"}
    blocked = [s for s in agent.memory.get_mission(result.mission_id)["steps"]
               if s.get("blocked")]
    assert len(blocked) == 1


def test_repeat_failure_counts_are_per_mission(monkeypatch, tmp_path):
    """计数按任务重置：上一次任务的失败不牵连下一次任务。"""
    agent, calls = _loop_agent(tmp_path, plan=[False] * 10, max_steps=2)
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: {"thought": "试", "tool": "flaky",
                                            "args": {"path": "/tmp/x"}})
    agent.run("http://127.0.0.1", "第一次")
    assert len(calls) == 2                      # 两次都够不着阈值（限 3）
    agent.run("http://127.0.0.1", "第二次")
    assert len(calls) == 4                      # 若计数不重置，第 4 次会被拦


def test_fingerprint_is_key_order_independent(tmp_path):
    """指纹与参数键序无关（同一调用的不同序列化形态算同一次）。"""
    agent, _ = _loop_agent(tmp_path, plan=[False], max_steps=1)
    a = PenAgent._fingerprint("flaky", {"path": "/x", "mode": "1"})
    b = PenAgent._fingerprint("flaky", {"mode": "1", "path": "/x"})
    assert a == b
    assert a != PenAgent._fingerprint("flaky", {"path": "/x"})
