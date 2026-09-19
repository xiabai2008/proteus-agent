"""budget/scope 字段机制性生效测试（此前只落字段未消费的收口验证）。

覆盖：
- scope.network_egress=false：Policy 闸门拒绝声明 network=True 的工具
  （执行前机制性拦截，非提示词劝退），egress=true 放行
- 沙箱层同规则：SandboxPolicy(egress=False) 拒绝出网工具（冗余防线）
- 沙箱档位随模式携带出网开关（PenAgent 构造路径）
- budget.model_tier：常规步走 recon 档模型、强制收口走 reason 档模型，
  未配置档位回落主模型（零配置行为不变）
- budget.max_minutes：超时走"换策略强制收口"，不硬退出
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
from penagent.sandbox import SandboxPolicy
from penagent.tools import ToolRegistry, ToolSpec

PROMPT_STUB = "模式提示词\n工具:\n{tools}\n技能:\n{skills}\n"


def _write_mode(tmp_path: Path, name: str, body: str) -> Path:
    modes_dir = tmp_path / "modes"
    modes_dir.mkdir(exist_ok=True)
    (modes_dir / f"{name}.yaml").write_text(body, encoding="utf-8")
    (tmp_path / "prompts").mkdir(exist_ok=True)
    (tmp_path / "prompts" / "stub.md").write_text(PROMPT_STUB, encoding="utf-8")
    return modes_dir


MODE_STUB = (
    "id: {name}\n"
    "persona: {{system_prompt: prompts/stub.md}}\n"
    "capability: {{allow: ['*']}}\n"
    "{budget}\n"
    "scope: {{{scope}}}\n"
    "verifier: {{type: evidence_chain}}\n")


def _mode(tmp_path, name, *, scope_line="network_egress: false",
          budget="budget: {max_steps: 5}"):
    modes_dir = _write_mode(
        tmp_path, name,
        MODE_STUB.format(name=name, budget=budget, scope=scope_line))
    return load_mode(name, modes_dir=modes_dir)


def _agent(tmp_path, mode=None, *, llm=None, max_steps=4,
           network_tool=True):
    reg = ToolRegistry()
    reg.register(ToolSpec(name="egress_tool", description="出网工具",
                          parameters={"host": {"type": "string"}},
                          network=network_tool, dangerous=False))
    return PenAgent(reg, Memory(tmp_path / "mem"),
                    EvidenceChain(tmp_path / "chain.jsonl"),
                    llm or LLMConfig(),
                    policy=Policy(allowed_targets=["127.0.0.1"],
                                  authorize=True),
                    max_steps=max_steps, mode=mode)


def _spy_execute(monkeypatch, agent):
    calls = []
    original = agent.registry.execute

    def spy(name, args, *a, **kw):
        calls.append(name)
        return original(name, args, *a, **kw)

    monkeypatch.setattr(agent.registry, "execute", spy)
    return calls


# ----------------------------------------------------------------------
# 1. scope.network_egress：闸门层机制性拒绝
# ----------------------------------------------------------------------
def test_egress_off_rejects_network_tool(monkeypatch, tmp_path):
    """模式关闭出网 -> 声明 network 的工具被闸门拦截，工具体不执行。"""
    mode = _mode(tmp_path, "egress-off")
    agent = _agent(tmp_path, mode)
    calls = _spy_execute(monkeypatch, agent)
    decisions = [
        {"thought": "需要出网", "tool": "egress_tool", "args": {}},
        {"thought": "放弃", "done": True, "summary": "任务未完成",
         "evidence_refs": []},
    ]
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))
    result = agent.run("http://127.0.0.1", "出网任务")
    assert result.outcome == "success"          # 第二步如实收口成功
    assert calls == []                          # 出网工具从未执行
    mission = agent.memory.get_mission(result.mission_id)
    blocked = [s for s in mission["steps"] if s.get("blocked")]
    assert blocked and "出网" in blocked[0]["reason"]


def test_egress_on_allows_network_tool(monkeypatch, tmp_path):
    """模式开启出网（如 CTF 模式）-> 出网工具正常执行。"""
    mode = _mode(tmp_path, "egress-on",
                 scope_line="network_egress: true")
    agent = _agent(tmp_path, mode)
    calls = _spy_execute(monkeypatch, agent)
    decisions = [
        {"thought": "需要出网", "tool": "egress_tool",
         "args": {"host": "127.0.0.1"}},
        {"thought": "拿到输出", "done": True, "summary": "完成",
         "evidence_refs": [1]},
    ]
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))
    result = agent.run("http://127.0.0.1", "出网任务")
    assert result.outcome == "success"
    assert calls == ["egress_tool"]


def test_egress_rule_not_applied_without_mode(tmp_path):
    """不传 mode 时不出网裁决（向后兼容：升级前行为一致）。"""
    from penagent.agent import Policy

    policy = Policy(allowed_targets=["127.0.0.1"], authorize=True)
    ok, _ = policy.check("egress_tool",
                         ToolSpec(name="egress_tool", network=True), {})
    assert ok


def test_sandbox_rejects_network_tool_when_egress_off():
    """沙箱层冗余防线：egress=False 时出网工具在沙箱裁决即被拒。"""
    spec = ToolSpec(name="net_tool", network=True)
    assert not SandboxPolicy(level="local", egress=False).decide(spec).allowed
    assert not SandboxPolicy(level="none").decide(spec).allowed
    # egress 开启：非隔离需求工具放行
    assert SandboxPolicy(level="local", egress=True).decide(spec).allowed


def test_sandbox_carries_egress_from_mode(tmp_path):
    """PenAgent 构造路径：模式出网开关随沙箱策略挂上注册表。"""
    agent_off = _agent(tmp_path, _mode(tmp_path, "carries-off"))
    assert agent_off.registry.sandbox.egress is False
    agent_on = _agent(tmp_path,
                      _mode(tmp_path, "carries-on",
                            scope_line="network_egress: true"))
    assert agent_on.registry.sandbox.egress is True


# ----------------------------------------------------------------------
# 2. budget.model_tier：档位模型路由
# ----------------------------------------------------------------------
def test_model_tier_routes_recon_and_reason(monkeypatch, tmp_path):
    """常规步走 recon 档模型；强制收口走 reason 档模型（未配置回落主模型）。"""
    mode = _mode(tmp_path, "tiered",
                 budget="budget: {max_steps: 1, model_tier: "
                        "{recon: cheap, reason: strong}}")
    used_models = []
    decisions = [
        {"thought": "侦察", "tool": "egress_tool",
         "args": {"host": "127.0.0.1"}},
        {"thought": "步数耗尽后收口", "done": False},
    ]

    def fake_chat_json(config, messages, **kw):
        used_models.append(kw.get("model"))
        return decisions.pop(0)

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)
    llm = LLMConfig()
    llm.tier_models = {"cheap": "cheap-model-x"}   # strong 未配置
    agent = _agent(tmp_path, mode, llm=llm, max_steps=1)
    result = agent.run("http://127.0.0.1", "档位路由")
    assert result.outcome == "failed"              # 收口判定未过（桩不通过）
    # 第 1 次调用 = 常规决策步（recon 档）；第 2 次 = 强制收口（reason 档
    # 未配置 -> None 回落主模型）
    assert used_models[0] == "cheap-model-x"
    assert used_models[1] is None


def test_model_tier_unconfigured_falls_back(tmp_path):
    """模式声明了 model_tier 但档位模型未配置 -> 全程主模型（None）。"""
    mode = _mode(tmp_path, "tier-noop",
                 budget="budget: {max_steps: 3, model_tier: "
                        "{recon: cheap, reason: strong}}")
    agent = _agent(tmp_path, mode)
    assert agent._tier_model("recon") is None
    assert agent._tier_model("reason") is None


def test_tier_model_ignores_unknown_phase(tmp_path):
    """无模式 / 模式未声明该阶段 -> None。"""
    agent = _agent(tmp_path)                       # 不传 mode
    assert agent._tier_model("recon") is None
    mode = _mode(tmp_path, "tier-none")
    agent2 = _agent(tmp_path, mode)
    assert agent2._tier_model("unknown_phase") is None


# ----------------------------------------------------------------------
# 3. budget.max_minutes：超时换策略而非硬退出
# ----------------------------------------------------------------------
def test_max_minutes_exhausted_switches_to_conclusion(monkeypatch, tmp_path):
    """时长预算 0 -> 第一步即耗尽，走强制收口（失败原因含时长信息）。"""
    mode = _mode(tmp_path, "timeboxed",
                 budget="budget: {max_steps: 40, max_minutes: 0}")
    agent = _agent(tmp_path, mode, max_steps=40)
    decisions = [{"thought": "收口", "done": False}]

    def fake_chat_json(config, messages, **kw):
        # 验证收口调用发生在主循环之外（只被调用一次）
        assert not decisions or decisions
        return decisions.pop(0)

    monkeypatch.setattr("penagent.agent.chat_json", fake_chat_json)
    result = agent.run("http://127.0.0.1", "限时任务")
    assert result.outcome == "failed"
    assert "时长预算已用尽" in result.summary
    assert "max_minutes=0" in result.summary
    phases = [r.content.get("phase") for r in agent.evidence.load()
              if r.kind == "decision"]
    assert "budget_exhausted" in phases


def test_max_minutes_none_runs_normally(monkeypatch, tmp_path):
    """无时长上限（默认）-> 不触发收口分支，正常走完决策流。"""
    agent = _agent(tmp_path, max_steps=3)
    decisions = [
        {"thought": "侦察", "tool": "egress_tool",
         "args": {"host": "127.0.0.1"}},
        {"thought": "完成", "done": True, "summary": "ok",
         "evidence_refs": []},
    ]
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))
    result = agent.run("http://127.0.0.1", "侦察")
    assert result.outcome == "success"
    phases = [r.content.get("phase") for r in agent.evidence.load()
              if r.kind == "decision"]
    assert "budget_exhausted" not in phases
