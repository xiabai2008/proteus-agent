"""记忆分区与步数预算测试。

覆盖：
- missions / skills 按 memory_namespace 分区，同名技能两个分区互不干扰
- 内核按模式绑定分区名；_rank_skills 只在当前分区检索
- budget.max_steps 由模式决定；超限改换收口策略而非硬退出
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.memory import DEFAULT_NAMESPACE, Memory, Skill
from penagent.modes import load_mode
from penagent.tools import ToolRegistry, ToolSpec


def _skill(skill_id: str, title: str, fingerprint: str) -> Skill:
    return Skill(id=skill_id, title=title, target_fingerprint=fingerprint,
                 steps=["端口扫描"], tools=["http_test"],
                 evidence_refs=[1])


def _agent(tmp_path, mode=None, *, tools=("http_test",), authorize=True,
           max_steps=None, namespace_memory=None):
    reg = ToolRegistry()
    for name in tools:
        reg.register(ToolSpec(name=name, description=f"{name} 工具",
                              parameters={"host": {"type": "string"},
                                          "url": {"type": "string"}}))
    kwargs = {} if max_steps is None else {"max_steps": max_steps}
    return PenAgent(reg, namespace_memory or Memory(tmp_path / "mem"),
                    EvidenceChain(tmp_path / "chain.jsonl"), LLMConfig(),
                    policy=Policy(allowed_targets=["127.0.0.1"],
                                  authorize=authorize),
                    mode=mode, **kwargs)


def _mock_llm(monkeypatch, decisions):
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))


# ----------------------------------------------------------------------
# 1. 分区隔离
# ----------------------------------------------------------------------
def test_skills_isolated_between_namespaces(tmp_path):
    pentest = Memory(tmp_path, namespace="pentest-standard")
    ctf = Memory(tmp_path, namespace="ctf-web")

    pentest.add_skill(_skill("web-chain", "渗透 Web 链", "web service flask"))
    # 同名技能放进另一个分区：两边各自独立
    ctf.add_skill(_skill("web-chain", "CTF Web 链", "web ctf flag"))

    assert [s.title for s in pentest.list_skills()] == ["渗透 Web 链"]
    assert [s.title for s in ctf.list_skills()] == ["CTF Web 链"]
    # 关键词命中只发生在本分区内（find_skills 的匹配语义不变）
    assert [s.title for s in pentest.find_skills("web service")] == ["渗透 Web 链"]
    assert [s.title for s in ctf.find_skills("web service")] == ["CTF Web 链"]
    # 反向：各自看不到对方分区的内容
    # （"service"/"flask" 只在渗透分区技能的指纹里，"ctf"/"flag" 只在 CTF 分区里）
    assert ctf.find_skills("service flask") == []
    assert pentest.find_skills("ctf flag") == []


def test_missions_isolated_between_namespaces(tmp_path):
    pentest = Memory(tmp_path, namespace="pentest-standard")
    ctf = Memory(tmp_path, namespace="ctf-web")

    mid = pentest.new_mission("http://127.0.0.1", "侦察")
    pentest.add_step(mid, {"step": 1, "tool": "http_test", "ok": True})

    assert [m["id"] for m in pentest.list_missions()] == [mid]
    assert ctf.list_missions() == []
    with pytest.raises(FileNotFoundError):
        ctf.get_mission(mid)


def test_for_namespace_shares_root(tmp_path):
    base = Memory(tmp_path)
    assert base.namespace == DEFAULT_NAMESPACE
    other = base.for_namespace("ctf-web")
    assert other.root == base.root and other.namespace == "ctf-web"
    assert other.skills_dir != base.skills_dir
    assert set(base.for_namespace("ctf-web").namespaces()) == {
        DEFAULT_NAMESPACE, "ctf-web"}
    # 默认分区与历史布局兼容：不再有根目录下的 missions/skills 文件散落
    assert base.missions_dir.parent.name == "missions"


@pytest.mark.parametrize("bad", ["..", ".", "a/b", "a\\b", "c:d", ""])
def test_invalid_namespace_rejected(tmp_path, bad):
    if bad == "":
        assert Memory(tmp_path, namespace=bad).namespace == DEFAULT_NAMESPACE
        return
    with pytest.raises(ValueError):
        Memory(tmp_path, namespace=bad)


# ----------------------------------------------------------------------
# 2. 内核按模式绑定分区，_rank_skills 只在当前分区检索
# ----------------------------------------------------------------------
def test_agent_binds_mode_namespace(tmp_path):
    agent = _agent(tmp_path, load_mode("ctf-web"))
    assert agent.memory.namespace == "ctf-web"
    assert _agent(tmp_path, None).memory.namespace == DEFAULT_NAMESPACE


def test_rank_skills_scoped_to_mode_namespace(monkeypatch, tmp_path):
    """渗透分区里的技能不会被 CTF 模式检索到（反之亦然）。"""
    Memory(tmp_path / "mem", namespace="pentest-standard").add_skill(
        _skill("p1", "渗透 Web 链", "web service flask"))
    Memory(tmp_path / "mem", namespace="ctf-web").add_skill(
        _skill("c1", "CTF Web 链", "web service flask"))

    _mock_llm(monkeypatch, [
        {"thought": "收口", "done": True, "summary": "flag{x}"},
    ])
    ctf_agent = _agent(tmp_path, load_mode("ctf-web"))
    ctf_result = ctf_agent.run("http://127.0.0.1", "解题",
                               fingerprint="web service flask")
    assert ctf_result.injected_skills == ["CTF Web 链"]

    # 同一根目录、不传模式：落在默认分区，看不到上面两个分区的技能
    _mock_llm(monkeypatch, [
        {"thought": "收口", "done": True, "summary": "ok"},
    ])
    plain = _agent(tmp_path, None)
    plain_result = plain.run("http://127.0.0.1", "侦察",
                             fingerprint="web service flask")
    assert plain_result.injected_skills == []


# ----------------------------------------------------------------------
# 3. 步数预算：模式决定上限；超限换策略而非硬退出
# ----------------------------------------------------------------------
def test_budget_max_steps_from_mode(tmp_path):
    assert _agent(tmp_path, load_mode("ctf-web")).max_steps == 60
    assert _agent(tmp_path, load_mode("pentest-standard")).max_steps == 40
    assert _agent(tmp_path, None).max_steps == 12
    # 显式传参优先于模式预算
    assert _agent(tmp_path, load_mode("ctf-web"), max_steps=7).max_steps == 7


def test_budget_exhausted_switches_to_conclude(monkeypatch, tmp_path):
    """步数耗尽后追加一轮强制收口：任务以收口结论正常结束，不崩溃。"""
    _mock_llm(monkeypatch, [
        {"thought": "试探 1", "tool": "http_test", "args": {"url": "http://127.0.0.1"}},
        {"thought": "试探 2", "tool": "http_test", "args": {"url": "http://127.0.0.1"}},
        {"thought": "收口", "done": True, "summary": "发现的结论",
         "evidence_refs": [1]},          # 第 3 次调用 = 换策略后的收口轮
    ])
    agent = _agent(tmp_path, None, max_steps=2)
    result = agent.run("http://127.0.0.1", "侦察")

    assert result.outcome == "success"
    assert result.summary == "发现的结论"
    assert result.evidence_refs == [1]
    # 收口轮被留证标记
    phases = [r.content.get("phase") for r in agent.evidence.load()]
    assert "budget_exhausted" in phases and "budget_concluded" in phases


def test_budget_exhausted_conclude_still_verified(monkeypatch, tmp_path):
    """换策略不等于放宽判据：收口轮仍过判定器，未通过则失败（不崩溃）。"""
    _mock_llm(monkeypatch, [
        {"thought": "试探 1", "tool": "http_test", "args": {"url": "http://127.0.0.1"}},
        {"thought": "仍在调工具", "tool": "http_test",
         "args": {"url": "http://127.0.0.1"}},   # 收口轮仍要调工具 -> 不算收口
    ])
    agent = _agent(tmp_path, None, max_steps=1)
    result = agent.run("http://127.0.0.1", "侦察")

    assert result.outcome == "failed"
    assert "步数预算已用尽" in result.summary


def test_budget_exhausted_in_ctf_mode_still_needs_flag(monkeypatch, tmp_path):
    """CTF 模式换策略后仍以 flag 收口为准。"""
    _mock_llm(monkeypatch, [
        {"thought": "试探 1", "tool": "http_test", "args": {"url": "http://127.0.0.1"}},
        {"thought": "试探 2", "tool": "http_test", "args": {"url": "http://127.0.0.1"}},
        {"thought": "收口", "done": True, "summary": "flag{budget-ok}"},
    ])
    agent = _agent(tmp_path, load_mode("ctf-web"), tools=("http_test",),
                   max_steps=2)
    result = agent.run("http://127.0.0.1", "解题")

    assert result.outcome == "success"
    assert "flag{budget-ok}" in result.summary


# ----------------------------------------------------------------------
# R-3：mode.skills 作为技能包过滤
#
# 该字段此前**无任何消费方**（仅在 Web 控制台展示与测试断言中出现），与
# AGENTS.md 第 4 节声明的"技能检索过滤"语义不符。这里让它机制性生效：
# 按 Skill.category 过滤本模式的技能包。语义上只过滤"明确标注了 category
# 且不在白名单内"的技能——未标注的保留，避免静默丢弃历史数据。
# ----------------------------------------------------------------------
def _mode_with_skills(skills):
    """构造带 skills 声明的模式档案（ModeProfile 冻结，用 replace）。"""
    from dataclasses import replace

    from penagent.modes import load_mode

    return replace(load_mode("pentest-standard"), skills=tuple(skills))


def test_mode_skills_filter_drops_out_of_pack_category(tmp_path):
    """category 不在 mode.skills 内的技能不被注入。"""
    mem = Memory(tmp_path, namespace="pentest-standard")
    mem.add_skill(Skill(id="s-sqli", title="SQLi 链", category="sqli",
                        target_fingerprint="web flask", evidence_refs=[1]))
    mem.add_skill(Skill(id="s-xss", title="XSS 链", category="xss",
                        target_fingerprint="web flask", evidence_refs=[1]))
    agent = _agent(tmp_path, mode=_mode_with_skills(["sqli"]),
                   namespace_memory=mem)

    picked = agent._filter_mode_skills(agent.memory.find_skills("web flask"))
    assert [s.id for s in picked] == ["s-sqli"]


def test_uncategorized_skill_survives_mode_filter(tmp_path):
    """未标注 category 的技能保留：过滤不得静默丢弃历史数据。"""
    mem = Memory(tmp_path, namespace="pentest-standard")
    mem.add_skill(Skill(id="s-old", title="未标注技能",
                        target_fingerprint="web flask"))
    agent = _agent(tmp_path, mode=_mode_with_skills(["sqli"]),
                   namespace_memory=mem)

    picked = agent._filter_mode_skills(agent.memory.find_skills("web flask"))
    assert [s.id for s in picked] == ["s-old"]


def test_empty_mode_skills_disables_filtering(tmp_path):
    """mode.skills 为空 = 不过滤（未声明技能包的模式行为不变）。"""
    mem = Memory(tmp_path, namespace="pentest-standard")
    mem.add_skill(Skill(id="s-xss", title="XSS 链", category="xss",
                        target_fingerprint="web flask"))
    agent = _agent(tmp_path, mode=_mode_with_skills([]),
                   namespace_memory=mem)

    picked = agent._filter_mode_skills(agent.memory.find_skills("web flask"))
    assert [s.id for s in picked] == ["s-xss"]


def test_no_mode_means_no_filtering(tmp_path):
    """无模式时不加这一层过滤（与升级前行为一致）。"""
    mem = Memory(tmp_path)
    mem.add_skill(Skill(id="s-xss", title="XSS 链", category="xss",
                        target_fingerprint="web flask"))
    agent = _agent(tmp_path, mode=None, namespace_memory=mem)

    picked = agent._filter_mode_skills(agent.memory.find_skills("web flask"))
    assert [s.id for s in picked] == ["s-xss"]


def test_reflect_extracts_skill_category(monkeypatch, tmp_path):
    """反思沉淀技能时提取 category——否则 mode.skills 过滤永远命中不了。"""
    from penagent.reflect import Reflector

    mem = Memory(tmp_path)
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    ev.append("tool_call", {"tool": "http_probe", "ok": True})
    mid = mem.new_mission("http://127.0.0.1", "测试目标")
    mem.add_step(mid, {"step": 1, "tool": "http_probe", "ok": True})

    monkeypatch.setattr("penagent.reflect.chat_json", lambda *a, **kw: {
        "outcome_analysis": "成功",
        "skill": {"title": "SQLi 注入链", "category": "sqli",
                  "target_fingerprint": "web flask",
                  "steps": ["探测"], "tools": ["sqlmap"],
                  "evidence_refs": [1]}})
    _, skill = Reflector().reflect(mid, mem, ev)
    assert skill is not None
    assert skill.category == "sqli"
