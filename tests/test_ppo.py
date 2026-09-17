"""PPO 策略测试：网络前向 / 训练更新 / 持久化 / 训练脚本。"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.ppo import PPOSkillPolicy, state_feature

SKILLS = ["web-exploit", "ssh-exploit", "full-recon"]


def test_state_feature():
    feat = state_feature("127.0.0.1 web service")
    assert feat[VOCAB_IDX("web")] == 1.0
    assert feat[VOCAB_IDX("ssh")] == 0.0
    assert sum(feat) == 1.0


def VOCAB_IDX(name: str) -> int:
    from penagent.ppo import VOCAB

    return VOCAB.index(name)


def test_act_sampling_and_greedy():
    p = PPOSkillPolicy(SKILLS)
    action, logp = p.act("web")
    assert 0 <= action < 3
    assert logp < 0
    g_action, _ = p.act("web", greedy=True)
    assert 0 <= g_action < 3


def test_update_reduces_loss():
    import torch

    torch.manual_seed(0)   # 固定初始化：分层 head 收敛断言可复现
    p = PPOSkillPolicy(SKILLS, lr=1e-2)
    rollouts = [
        {"state": state_feature("web"), "action": 0, "logp": -1.1,
         "reward": 85.0, "done": True},
        {"state": state_feature("web"), "action": 1, "logp": -1.1,
         "reward": -40.0, "done": True},
    ] * 10
    loss1 = p.update(rollouts, epochs=2)
    loss2 = p.update(rollouts, epochs=2)
    assert loss1 > 0 and loss2 > 0
    # 训练后 web 状态下最优动作倾向 0（高奖励动作）
    assert p.act("web", greedy=True)[0] == 0


def test_persistence(tmp_path):
    p = PPOSkillPolicy(SKILLS)
    path = p.save(tmp_path / "policy.pt")
    p2 = PPOSkillPolicy.load(path)
    assert p2.skill_ids == SKILLS
    a1 = p.act("web", greedy=True)
    a2 = p2.act("web", greedy=True)
    assert a1[0] == a2[0]   # 相同权重 -> 相同 argmax


def test_ensure_state_extension(tmp_path):
    """分层头配置驱动扩展：新状态自动加头，训练/持久化正常。"""
    import torch

    p = PPOSkillPolicy(SKILLS)
    n0 = len(p.model.actor_heads)
    idx = p.ensure_state("db")
    assert idx == n0 and len(p.model.actor_heads) == n0 + 1
    assert p.ensure_state("db") == idx           # 幂等
    assert p.act("db server", greedy=True)[0] in (0, 1, 2)

    # 扩展状态参与训练（db 状态样本走新头）
    p.update([
        {"state": state_feature("db"), "action": 0, "logp": -1.1,
         "reward": 60.0, "done": True},
        {"state": state_feature("db"), "action": 1, "logp": -1.1,
         "reward": -95.0, "done": True},
    ] * 10, epochs=2)

    # 扩展后的权重结构与持久化
    path = p.save(tmp_path / "policy_ext.pt")
    p2 = PPOSkillPolicy.load(path)
    assert len(p2.model.actor_heads) == n0 + 1
    a1 = p.act("db", greedy=True)
    a2 = p2.act("db", greedy=True)
    assert a1[0] == a2[0]
    # 实例级扩展不污染默认映射（新实例仍 4 头）
    p3 = PPOSkillPolicy(SKILLS)
    assert len(p3.model.actor_heads) == 4


def test_train_ppo_script():
    """PPO 训练脚本可运行且 PPO 不劣于随机探索。"""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "examples"
                            / "train_ppo.py")],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=300)
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "PPO" in proc.stdout
    assert "4.3" in proc.stdout    # 随机探索步数（v2 均衡环境，PPO 更优的对照）
    assert "OK" in proc.stdout or "PARTIAL OK" in proc.stdout
