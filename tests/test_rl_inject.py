"""RL 策略注入测试：Q 表最优技能优先注入。"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent, Policy
from penagent.builtin_tools import register_builtins
from penagent.evidence import EvidenceChain
from penagent.memory import Memory, Skill
from penagent.rl import SkillPolicy
from penagent.tools import ToolRegistry


def _agent(skill_policy, tmp_path):
    reg = ToolRegistry()
    register_builtins(reg)
    mem = Memory(tmp_path / "mem")
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    return PenAgent(reg, mem, ev, skill_policy=skill_policy)


def test_rank_rl_best_first(tmp_path):
    """RL 最优技能排最前（即使其成功率低于其他技能）。"""
    agent = _agent(None, tmp_path)
    skills = [
        Skill(id="s1", title="Web 框架识别与 web-exploit 利用",
              target_fingerprint="web http", successes=1, attempts=2,
              success_rate=0.5),
        Skill(id="s2", title="通用侦察", target_fingerprint="any",
              successes=3, attempts=3, success_rate=1.0),
    ]
    policy = SkillPolicy()
    policy.q["web"] = {"web-exploit": 90.0}
    agent.skill_policy = policy
    ranked = agent._rank_skills(skills, "127.0.0.1 web service")
    assert "web-exploit" in ranked[0].title


def test_rank_fallback_without_policy(tmp_path):
    """无策略时按成功率降序。"""
    agent = _agent(None, tmp_path)
    skills = [
        Skill(id="s1", title="慢技能", successes=1, attempts=4,
              success_rate=0.25),
        Skill(id="s2", title="快技能", successes=3, attempts=3,
              success_rate=1.0),
    ]
    ranked = agent._rank_skills(skills, "web")
    assert ranked[0].id == "s2"


def test_rank_unknown_state_fallback(tmp_path):
    """策略无该状态 Q 值 -> 回退成功率排序。"""
    policy = SkillPolicy()
    policy.q["web"] = {"web-exploit": 90.0}
    agent = _agent(policy, tmp_path)
    skills = [
        Skill(id="s1", title="web-exploit 技能", successes=1, attempts=2,
              success_rate=0.5),
        Skill(id="s2", title="高效技能", successes=2, attempts=2,
              success_rate=1.0),
    ]
    ranked = agent._rank_skills(skills, "ssh")   # 未训练状态
    assert ranked[0].id == "s2"


def test_run_uses_ranked_skills(tmp_path, monkeypatch):
    """run() 时 RL 策略影响注入技能顺序。"""
    reg = ToolRegistry()
    register_builtins(reg)
    mem = Memory(tmp_path / "mem")
    mem.add_skill(Skill(id="s1", title="web-exploit 利用技能",
                        target_fingerprint="web http", successes=1,
                        attempts=3, success_rate=0.33))
    mem.add_skill(Skill(id="s2", title="通用侦察技能",
                        target_fingerprint="any", successes=3,
                        attempts=3, success_rate=1.0))
    ev = EvidenceChain(tmp_path / "chain.jsonl")
    policy = SkillPolicy()
    policy.q["web"] = {"web-exploit": 80.0}

    decisions = [
        {"thought": "完成", "done": True, "summary": "ok",
         "evidence_refs": []},
    ]
    monkeypatch.setattr("penagent.agent.chat_json",
                        lambda c, m, **kw: decisions.pop(0))
    agent = PenAgent(reg, mem, ev, skill_policy=policy, max_steps=3)
    result = agent.run("http://127.0.0.1:8080", "侦察",
                       fingerprint="127.0.0.1 web service")
    assert result.injected_skills[0] == "web-exploit 利用技能"  # RL 优先


def test_rank_with_ppo_policy(tmp_path):
    """PPO 策略（神经网络）与 _rank_skills 接口兼容，按策略结果排序。"""

    import torch

    from penagent.ppo import PPOSkillPolicy, VOCAB

    p = PPOSkillPolicy(["web-exploit", "ssh-exploit", "full-recon"])
    # 手工设置 web 状态动作头：web 特征 → 动作 0（web-exploit）主导
    with torch.no_grad():
        head = p.model.actor_heads[1]   # web 状态头
        head.weight.zero_()
        head.bias.zero_()
        head.weight[0, 0] = 5.0         # 隐藏单元 0 特征分量对应权重
        p.model.shared[0].weight.zero_()
        p.model.shared[0].bias.zero_()
        p.model.shared[0].weight[0, VOCAB.index("web")] = 1.0

    agent = _agent(p, tmp_path)
    skills = [
        Skill(id="s1", title="web-exploit 最短链技能",
              target_fingerprint="web", successes=1, attempts=3,
              success_rate=0.33),
        Skill(id="s2", title="通用侦察", target_fingerprint="any",
              successes=3, attempts=3, success_rate=1.0),
    ]
    assert p.best_skill("127.0.0.1 web service") == "web-exploit"
    ranked = agent._rank_skills(skills, "127.0.0.1 web service")
    assert ranked[0].id == "s1"      # PPO 最优技能优先注入


def test_rank_stealth_mode(tmp_path):
    """对抗模式：非策略技能按隐蔽优先（exposure 升序）排序。"""
    from penagent.memory import Skill

    agent = _agent(None, tmp_path)
    skills = [
        Skill(id="loud", title="明文注入", target_fingerprint="web",
              successes=3, attempts=3, success_rate=1.0, exposure=2),
        Skill(id="stealth", title="注释混淆注入", target_fingerprint="web",
              successes=3, attempts=3, success_rate=1.0, exposure=0),
        Skill(id="legacy", title="旧技能", target_fingerprint="web",
              successes=2, attempts=2, success_rate=1.0),
    ]
    ranked = agent._rank_skills(skills, "web", stealth=True)
    assert [s.id for s in ranked] == ["stealth", "loud", "legacy"]
    # 默认模式保持成功率排序（向后兼容）
    ranked2 = agent._rank_skills(skills, "web")
    assert [s.id for s in ranked2] == ["loud", "stealth", "legacy"]
