"""M2 记忆闭环测试：技能沉淀 / 关键词指纹匹配 / 决策注入。"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.builtin_tools import register_builtins
from penagent.evidence import EvidenceChain
from penagent.memory import Memory, Skill
from penagent.tools import ToolRegistry


@pytest.fixture()
def env(tmp_path):
    reg = ToolRegistry()
    register_builtins(reg)
    return reg, Memory(tmp_path), EvidenceChain(tmp_path / "chain.jsonl")


def test_find_skills_keyword_overlap(env):
    """LLM 自然语言指纹与自动指纹按关键词共现匹配。"""
    _, mem, _ = env
    mem.add_skill(Skill(id="s1", title="Web 侦察",
                        target_fingerprint="任意 http 服务，尤其是 "
                        "Python/Flask 的 Web 应用"))
    mem.add_skill(Skill(id="s2", title="Java 扫描",
                        target_fingerprint="spring boot java 应用"))
    hits = mem.find_skills("127.0.0.1 web service")
    assert [s.id for s in hits] == ["s1"]     # "web" 关键词共现
    assert [s.id for s in mem.find_skills("192.168.1.5 java spring")] == ["s2"]
    assert mem.find_skills("192.168.1.5 tomcat") == []  # 无交集不命中


def test_skill_injected_into_mission(env, monkeypatch):
    """二次任务自动注入历史技能并记录到 mission。"""
    reg, mem, ev = env
    mem.add_skill(Skill(id="s1", title="Web 框架识别与 robots 侦察",
                        target_fingerprint="web http flask"))
    decisions = [
        {"thought": "直接总结", "done": True, "summary": "ok",
         "evidence_refs": []},
    ]
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))
    agent = PenAgent(reg, mem, ev, policy=Policy(), max_steps=3)
    result = agent.run("http://127.0.0.1:8081", "侦察",
                       fingerprint="127.0.0.1 web service")
    assert result.injected_skills == ["Web 框架识别与 robots 侦察"]
    assert mem.get_mission(result.mission_id)["outcome"] == "success"

def test_reflection_rejects_invalid_evidence(env, monkeypatch):
    from penagent.reflect import Reflector

    _, mem, ev = env
    ev.append("decision", {"step": 1})
    ev.append("tool_call", {"tool": "port_scan"})
    mid = mem.new_mission("http://x", "侦察")
    mem.add_step(mid, {"step": 1, "tool": "port_scan", "ok": True})
    mem.finish(mid, "success")

    def fake(config, messages, **kw):
        return {"outcome_analysis": "成功",
                "skill": {"title": "侦察技能", "target_fingerprint": "web",
                          "steps": ["端口扫描"], "tools": ["port_scan"],
                          "evidence_refs": [1, 99]}}

    monkeypatch.setattr("penagent.reflect.chat_json", fake)
    analysis, skill = Reflector().reflect(mid, mem, ev)
    assert skill is None
    assert "拒绝入库" in analysis


def test_reflection_saves_valid_skill(env, monkeypatch):
    from penagent.reflect import Reflector

    _, mem, ev = env
    ev.append("decision", {"step": 1})
    mid = mem.new_mission("http://x", "侦察")
    mem.finish(mid, "success")

    def fake(config, messages, **kw):
        return {"outcome_analysis": "成功",
                "skill": {"title": "侦察技能", "target_fingerprint": "web",
                          "steps": ["探测"], "tools": ["http_probe"],
                          "evidence_refs": [1]}}

    monkeypatch.setattr("penagent.reflect.chat_json", fake)
    _, skill = Reflector().reflect(mid, mem, ev)
    assert skill is not None
    assert skill.evidence_refs == [1]
    assert len(mem.list_skills()) == 1


def test_unavailable_cli_tool_not_registered(tmp_path):
    from penagent.external_tools import load_external_tools
    from penagent.tools import ToolRegistry

    cfg = tmp_path / "tools.json"
    cfg.write_text(json.dumps({"tools": {
        "ghost_scan": {"description": "x", "command": [
            "definitely-missing-bin", "{args}"]},
    }}), encoding="utf-8")
    reg = ToolRegistry()
    info = load_external_tools(reg, cfg)
    assert info["loaded"] == 0
    assert "ghost_scan" not in reg.names()


def test_chat_json_tolerates_wrapped_text(monkeypatch):
    from penagent.llm import chat_json

    monkeypatch.setattr(
        "penagent.llm.chat",
        lambda *a, **kw: '好的，结果如下：\n{"tool": "port_scan", '
                         '"args": {"host": "x"}}\n以上。')
    data = chat_json(None, [])
    assert data["tool"] == "port_scan"
