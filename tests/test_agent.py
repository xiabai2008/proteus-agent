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


# ----------------------------------------------------------------------
# R-40：LLM 输出不可解析 -> 回灌纠正提示重试（不吃步数），连续失败才收口
# ----------------------------------------------------------------------
def _mock_llm_script(monkeypatch, script, seen):
    """桩 LLM：按 script 依次出决策；元素是异常实例时抛出该异常。"""
    def fake_chat_json(config, messages, **kw):
        seen.append(messages[-1]["content"])
        item = script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)


def test_llm_parse_failure_is_retried_instead_of_failing(monkeypatch,
                                                         tmp_path):
    """一次不可解析输出不再废掉整轮：回灌纠正提示后继续。"""
    from penagent.llm import LLMOutputError

    agent, calls = _loop_agent(tmp_path, plan=[True], max_steps=3)
    seen = []
    _mock_llm_script(monkeypatch, [
        LLMOutputError("LLM 输出不是合法 JSON: Expecting value: line 1 col 1",
                       raw='<｜｜DSML｜｜ invoke name="flaky">'),
        {"thought": "重来", "tool": "flaky", "args": {"path": "/tmp/x"}},
        {"thought": "收口", "done": True, "summary": "ok", "evidence_refs": []},
    ], seen)
    result = agent.run("http://127.0.0.1", "解析失败")

    assert result.outcome == "success"
    assert len(calls) == 1
    # 纠正提示回灌到了下一次请求（点名禁 XML 标签 + 带上次输出片段）
    assert "只输出**一个 JSON 对象**" in seen[1]
    assert "<invoke>" in seen[1]
    assert 'invoke name="flaky"' in seen[1]
    # 每次失败都留证，含原始输出片段（事后能诊断是形态失误还是端点问题）
    retries = [r for r in agent.evidence.load()
               if r.content.get("phase") == "llm_parse_retry"]
    assert len(retries) == 1
    assert retries[0].content["attempt"] == 1
    assert 'invoke name="flaky"' in retries[0].content["raw"]
    assert agent.evidence.verify()["ok"]


def test_llm_parse_failure_gives_up_after_limit(monkeypatch, tmp_path):
    """连续不可解析到上限才收口，且收口理由写清是解析问题。"""
    from penagent.agent import LLM_PARSE_RETRY_LIMIT
    from penagent.llm import LLMOutputError

    agent, calls = _loop_agent(tmp_path, plan=[True], max_steps=3)
    tries = []

    def fake_chat_json(config, messages, **kw):
        tries.append(1)
        raise LLMOutputError("LLM 输出不是合法 JSON: Expecting value",
                             raw="彻底不是 JSON")

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)
    result = agent.run("http://127.0.0.1", "一直不合法")

    assert result.outcome == "failed"
    assert len(tries) == LLM_PARSE_RETRY_LIMIT + 1      # 重试 3 次后放弃
    assert f"输出连续 {LLM_PARSE_RETRY_LIMIT + 1} 次不可解析" in result.summary
    assert len(calls) == 0                              # 从未执行工具
    retries = [r for r in agent.evidence.load()
               if r.content.get("phase") == "llm_parse_retry"]
    assert len(retries) == LLM_PARSE_RETRY_LIMIT + 1
    assert agent.evidence.verify()["ok"]


def test_llm_transport_error_still_fails_fast(monkeypatch, tmp_path):
    """调用失败（网络/HTTP/超时）不重试：重试同一请求没有意义。"""
    from penagent.llm import LLMError

    agent, calls = _loop_agent(tmp_path, plan=[True], max_steps=3)
    tries = []

    def fake_chat_json(config, messages, **kw):
        tries.append(1)
        raise LLMError("LLM API 不可达: Connection refused")

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)
    result = agent.run("http://127.0.0.1", "端点挂了")

    assert result.outcome == "failed"
    assert len(tries) == 1                              # 一次即收口
    assert "LLM 调用失败" in result.summary
    assert len(calls) == 0


def test_llm_parse_retry_does_not_consume_step_budget(monkeypatch, tmp_path):
    """解析失败不记步数：max_steps=1 时唯一那一步仍能真正执行工具。"""
    from penagent.llm import LLMOutputError

    agent, calls = _loop_agent(tmp_path, plan=[True], max_steps=1)
    _mock_llm_script(monkeypatch, [
        LLMOutputError("LLM 输出不是合法 JSON", raw="乱码"),
        {"thought": "用掉唯一一步", "tool": "flaky",
         "args": {"path": "/tmp/x"}},
        {"thought": "收口", "done": True, "summary": "ok", "evidence_refs": []},
    ], [])
    result = agent.run("http://127.0.0.1", "步数预算")

    assert len(calls) == 1                  # 未被重试吞掉
    assert result.outcome == "success"


def test_llm_parse_retry_covers_forced_conclusion(monkeypatch, tmp_path):
    """预算耗尽后的强制收口同样可重试：最后一次决策的形态失误不废整轮。"""
    from penagent.llm import LLMOutputError

    agent, calls = _loop_agent(tmp_path, plan=[True], max_steps=1)
    _mock_llm_script(monkeypatch, [
        {"thought": "先用一步", "tool": "flaky", "args": {"path": "/tmp/x"}},
        LLMOutputError("LLM 输出不是合法 JSON",
                       raw='<invoke name="flaky">'),
        {"thought": "收口", "done": True, "summary": "ok", "evidence_refs": []},
    ], [])
    result = agent.run("http://127.0.0.1", "收口重试")

    assert len(calls) == 1
    assert result.outcome == "success"
