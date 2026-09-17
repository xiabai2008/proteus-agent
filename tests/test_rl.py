"""RL 策略进化测试：Q-learning 技能选择策略。"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.rl import SkillPolicy


def test_state_discretization():
    assert SkillPolicy.state("127.0.0.1 web service") == "web"
    assert SkillPolicy.state("web ssh flask") == "flask+ssh+web"
    assert SkillPolicy.state("random unknown thing") == "unknown"


def test_choose_epsilon_greedy():
    import random

    p = SkillPolicy(epsilon=1.0)   # 全探索：随机选
    skills = ["a", "b", "c"]
    chosen = {p.choose("s", skills, random.Random(i)) for i in range(30)}
    assert chosen <= set(skills)
    # ε=0 且 Q 有值：argmax
    p.q["s"] = {"a": 10.0, "b": 5.0}
    p2 = SkillPolicy(epsilon=0.0)
    p2.q["s"] = p.q["s"]
    assert p2.choose("s", skills, random.Random(1)) == "a"


def test_q_update_converges_to_best_action():
    """同一状态反复给动作 a 高奖励 -> a 的 Q 值最高。"""
    p = SkillPolicy(epsilon=0.1, alpha=0.2, gamma=0.9)
    state = "web"
    for _ in range(50):
        p.update(state, "a", 85.0, "web")     # 成功且步数少
        p.update(state, "b", 60.0, "web")     # 成功但步数多
        p.update(state, "c", -40.0, "web")    # 失败
    assert p.best_skill(state) == "a"
    values = p.q[state]
    assert values["a"] > values["b"] > values["c"]


def test_persistence(tmp_path):
    p = SkillPolicy()
    p.q["web"] = {"web-exploit": 90.0}
    path = p.save(tmp_path / "policy.json")
    p2 = SkillPolicy.load(path)
    assert p2.best_skill("web") == "web-exploit"
    p3 = SkillPolicy.load(tmp_path / "missing.json")
    assert p3.q == {}


def test_train_script_runs():
    """RL 训练脚本可运行且 RL 策略优于随机探索。"""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "examples"
                            / "train_policy.py")],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=300)
    assert proc.returncode == 0, proc.stderr[-500:]
    out = proc.stdout
    assert "RL" in out
    assert "[OK]" in out          # 收敛结论
    assert "web-exploit" in out   # Q 表摘要（含最优技能）
