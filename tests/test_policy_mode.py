"""模式驱动的 Policy 裁决测试。

覆盖：
- capability.constraints 参数冻结（单元 + 主循环实参 + CLI 渲染）
- capability.deny / permission.hard_deny 机制性拒绝（执行前拦住，不靠提示词）
- permission.require_confirm 记为 blocked 待人工确认
- scope.target_allowlist 只可收紧
- 不传 mode 时与升级前行为完全一致（向后兼容）
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
from penagent.tools import FROZEN_ARGS_KEY, ToolRegistry, ToolSpec

TOOLS = {"nuclei": False, "sqlmap": False, "msf_exploit": True,
         "mimikatz": True, "http_test": False, "httpx": False}


def _agent(tmp_path, mode=None, *, tools=None, targets=None,
           authorize=False, max_steps=4):
    reg = ToolRegistry()
    for name, dangerous in (tools or TOOLS).items():
        reg.register(ToolSpec(name=name, description=f"{name} 工具",
                              parameters={"host": {"type": "string"},
                                          "url": {"type": "string"}},
                              dangerous=dangerous))
    return PenAgent(reg, Memory(tmp_path / "mem"),
                    EvidenceChain(tmp_path / "chain.jsonl"), LLMConfig(),
                    policy=Policy(allowed_targets=targets or ["127.0.0.1"],
                                  authorize=authorize),
                    max_steps=max_steps, mode=mode)


def _mock_llm(monkeypatch, decisions):
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))


def _spy_execute(monkeypatch, agent):
    """记录真正被执行到的工具调用（验证"机制性拦截"而非提示词拒绝）。"""
    calls = []
    original = agent.registry.execute

    def spy(name, args, *a, **kw):
        calls.append((name, dict(args)))
        return original(name, args, *a, **kw)

    monkeypatch.setattr(agent.registry, "execute", spy)
    return calls


def _blocked_steps(agent, mission_id):
    mission = agent.memory.get_mission(mission_id)
    return [s for s in mission["steps"] if s.get("blocked")]


def _blocked_evidence(agent):
    return [r.content for r in agent.evidence.load()
            if r.kind == "tool_call" and r.content.get("blocked")]


# ----------------------------------------------------------------------
# 1. capability.constraints：执行前冻结追加
# ----------------------------------------------------------------------
def test_constraint_appended_to_args(monkeypatch, tmp_path):
    mode = load_mode("pentest-standard")
    agent = _agent(tmp_path, mode, authorize=True)
    calls = _spy_execute(monkeypatch, agent)
    _mock_llm(monkeypatch, [
        {"thought": "扫", "tool": "sqlmap",
         "args": {"url": "http://127.0.0.1/x"}},
        {"thought": "完成", "done": True, "summary": "ok"},
    ])
    agent.run("http://127.0.0.1", "约束冻结")

    assert [c[0] for c in calls] == ["sqlmap"]
    executed = calls[0][1]
    assert executed[FROZEN_ARGS_KEY] == "--batch --level 3 --risk 1"
    assert executed["url"] == "http://127.0.0.1/x"     # 原参数保留
    # 模式未配置约束的工具不受影响
    assert FROZEN_ARGS_KEY not in Policy(mode=mode).apply_constraints("httpx", {})


def test_frozen_args_rendered_as_cli_tokens():
    """冻结串按命令行 token 追加到命令尾部（CLI 工具真正能吃到）。"""
    policy = Policy(mode=load_mode("pentest-standard"))
    spec = ToolSpec(name="nuclei", kind="cli", command=["nuclei", "{args}"])
    args = policy.apply_constraints("nuclei", {"target": "http://127.0.0.1"})
    parts = ToolRegistry._cli_args(spec, args)
    assert parts == ["--target", "http://127.0.0.1",
                     "-severity", "low,medium,high", "-c", "25"]


# ----------------------------------------------------------------------
# 2. capability.deny / hard_deny：执行前直接拒绝
# ----------------------------------------------------------------------
def test_capability_deny_blocks_before_execution(monkeypatch, tmp_path):
    """allow 为 "*" 时仍受 deny 约束；拒绝发生在执行之前，不是提示词劝说。"""
    mode = load_mode("pentest-standard")
    agent = _agent(tmp_path, mode, authorize=True, tools={"msf_exploit": False})
    calls = _spy_execute(monkeypatch, agent)
    _mock_llm(monkeypatch, [
        {"thought": "上 msf", "tool": "msf_exploit",
         "args": {"host": "127.0.0.1"}},
        {"thought": "完成", "done": True, "summary": "未执行"},
    ])
    result = agent.run("http://127.0.0.1", "尝试被禁工具")

    assert calls == []                                   # 一次都没执行
    blocked = _blocked_steps(agent, result.mission_id)
    assert len(blocked) == 1
    assert "禁用" in blocked[0]["reason"] and "msf_exploit" in blocked[0]["reason"]
    assert _blocked_evidence(agent)[0]["level"] == "deny"


def test_ctf_mode_denied_tool_unreachable(monkeypatch, tmp_path):
    """CTF 模式下 nuclei 既不在注册表，也无法执行。"""
    agent = _agent(tmp_path, load_mode("ctf-web"),
                   tools={"nuclei": False, "http_test": False})
    assert agent.registry.get("nuclei") is None
    calls = _spy_execute(monkeypatch, agent)
    _mock_llm(monkeypatch, [
        {"thought": "扫一扫", "tool": "nuclei", "args": {"url": "http://127.0.0.1"}},
        {"thought": "完成", "done": True, "summary": "flag{ctf-ok}"},
    ])
    result = agent.run("http://127.0.0.1", "越界调用")

    assert calls == []
    blocked = _blocked_steps(agent, result.mission_id)
    assert "ctf-web" in blocked[0]["reason"] and "禁用" in blocked[0]["reason"]


def test_hard_deny_not_releasable_by_authorize(tmp_path):
    """hard_deny 是绝对的：运行期授权也不能放行。"""
    policy = Policy(authorize=True, mode=load_mode("pentest-standard"))
    spec = ToolSpec(name="mimikatz", dangerous=True)
    ok, reason = policy.check("mimikatz", spec, {"host": "127.0.0.1"})
    assert not ok and "deny" in reason
    # 同一档位下未列入禁用的工具则放行
    ok2, _ = policy.check("httpx", ToolSpec(name="httpx"),
                          {"host": "127.0.0.1"})
    assert ok2


# ----------------------------------------------------------------------
# 3. permission.require_confirm：待人工确认
# ----------------------------------------------------------------------
def test_require_confirm_pending_without_authorize(monkeypatch, tmp_path):
    mode = load_mode("pentest-standard")
    agent = _agent(tmp_path, mode, authorize=False)
    calls = _spy_execute(monkeypatch, agent)
    _mock_llm(monkeypatch, [
        {"thought": "注入测试", "tool": "sqlmap",
         "args": {"url": "http://127.0.0.1/x"}},
        {"thought": "完成", "done": True, "summary": "待确认"},
    ])
    result = agent.run("http://127.0.0.1", "确认档位")

    assert calls == []                                   # 未确认即未执行
    blocked = _blocked_steps(agent, result.mission_id)
    assert "待人工确认" in blocked[0]["reason"]
    assert "ask" in blocked[0]["reason"]                 # 标注档位
    assert _blocked_evidence(agent)[0]["level"] == "ask"


def test_require_confirm_released_by_authorize(monkeypatch, tmp_path):
    """操作者已授权（--authorize）时，ask 档位放行。"""
    agent = _agent(tmp_path, load_mode("pentest-standard"), authorize=True)
    calls = _spy_execute(monkeypatch, agent)
    _mock_llm(monkeypatch, [
        {"thought": "注入测试", "tool": "sqlmap",
         "args": {"url": "http://127.0.0.1/x"}},
        {"thought": "完成", "done": True, "summary": "已执行"},
    ])
    agent.run("http://127.0.0.1", "确认档位")
    assert [c[0] for c in calls] == ["sqlmap"]


# ----------------------------------------------------------------------
# 4. scope.target_allowlist：只可收紧
# ----------------------------------------------------------------------
def _write_mode(tmp_path: Path, name: str, allowlist_line: str) -> Path:
    modes_dir = tmp_path / "modes"
    modes_dir.mkdir(exist_ok=True)
    (modes_dir / f"{name}.yaml").write_text(
        "id: narrow\n"
        "persona: {system_prompt: prompts/stub.md}\n"
        "capability: {allow: ['*']}\n"      # 只考察 scope，能力全放开
        "budget: {max_steps: 5}\n"
        "verifier: {type: evidence_chain}\n"
        f"{allowlist_line}\n", encoding="utf-8")
    (tmp_path / "prompts").mkdir(exist_ok=True)
    (tmp_path / "prompts" / "stub.md").write_text("模板", encoding="utf-8")
    return modes_dir


def test_mode_allowlist_cannot_widen(tmp_path):
    """模式声明了运行期从未授权的目标 -> 取交集为空，一律拒绝。"""
    from penagent.modes import load_mode as load

    modes_dir = _write_mode(tmp_path, "narrow",
                            "scope: {target_allowlist: [example.com]}")
    mode = load("narrow", modes_dir=modes_dir)
    # authorize=True 放行默认 ask 档位，单独考察 scope 行为
    policy = Policy(allowed_targets=["127.0.0.1"], authorize=True, mode=mode)
    ok, reason = policy.check("httpx", ToolSpec(name="httpx"),
                              {"url": "http://example.com"})
    assert not ok and "授权范围" in reason


def test_mode_allowlist_can_narrow_narrower(tmp_path):
    """模式白名单与运行期授权取交集：交集内放行，交集外拒绝。"""
    from penagent.modes import load_mode as load

    modes_dir = _write_mode(tmp_path, "narrow",
                            "scope: {target_allowlist: [127.0.0.1]}")
    mode = load("narrow", modes_dir=modes_dir)
    policy = Policy(allowed_targets=["127.0.0.1", "example.com"],
                    authorize=True, mode=mode)
    assert policy.allowed_targets == ["127.0.0.1"]
    assert policy.check("httpx", ToolSpec(name="httpx"),
                        {"host": "127.0.0.1"})[0]
    assert not policy.check("httpx", ToolSpec(name="httpx"),
                            {"host": "example.com"})[0]


def test_required_allowlist_keeps_runtime_targets():
    """两个基准模式都声明 required：不改变运行期授权范围。"""
    policy = Policy(allowed_targets=["127.0.0.1"],
                    mode=load_mode("pentest-standard"))
    assert policy.allowed_targets == ["127.0.0.1"]
    assert policy.check("httpx", ToolSpec(name="httpx"),
                        {"host": "127.0.0.1"})[0]


# ----------------------------------------------------------------------
# 5. 向后兼容：不传 mode 时行为与升级前一致
# ----------------------------------------------------------------------
def test_backward_compatible_defaults():
    policy = Policy()
    assert policy.allowed_targets == ["127.0.0.1", "localhost"]
    assert policy.mode is None
    # 高危未授权 -> 拒绝，原因文本与升级前一致
    ok, reason = policy.check("rayscan_quick",
                              ToolSpec(name="rayscan_quick", dangerous=True),
                              {"target": "http://127.0.0.1"})
    assert not ok and "高危" in reason and "--authorize" in reason
    # 越界目标 -> 拒绝，原因文本与升级前一致
    ok2, reason2 = policy.check("port_scan", ToolSpec(name="port_scan"),
                                {"host": "192.168.1.1"})
    assert not ok2 and "授权范围" in reason2
    # 约束与档位：无模式时均为空操作
    args = {"host": "127.0.0.1"}
    assert policy.apply_constraints("sqlmap", args) is args
    assert policy.level_for("sqlmap") == "ok"


def test_backward_compatible_agent_loop(monkeypatch, tmp_path):
    """不传 mode 的内核：越权与高危拦截行为、留证字段保持不变。"""
    agent = _agent(tmp_path, None, tools={"rayscan_quick": False})
    calls = _spy_execute(monkeypatch, agent)
    _mock_llm(monkeypatch, [
        {"thought": "打外网", "tool": "rayscan_quick",
         "args": {"host": "192.168.1.1"}},
        {"thought": "收工", "done": True, "summary": "ok"},
    ])
    result = agent.run("http://127.0.0.1", "越权尝试")

    assert calls == []
    blocked = _blocked_steps(agent, result.mission_id)
    assert len(blocked) == 1
    assert "授权范围" in blocked[0]["reason"]
    # 未传 mode 时不得出现模式裁决字样
    assert "模式" not in blocked[0]["reason"]
