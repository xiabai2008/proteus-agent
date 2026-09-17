"""PPO 技能选择策略：Actor-Critic 网络 + PPO 训练（替代表格 Q-learning）。

- 状态特征：目标指纹服务关键词多热向量（web/ssh/db/...）
- Actor：共享 backbone + 每状态独立动作头（分层：状态条件化不互相串扰）
- Critic：MLP -> 状态价值
- 训练：rollout 收集 -> per-state 归一化优势 -> PPO clip 更新
- 依赖：torch（CPU 版即可，网络极小训练秒级）
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Optional

import torch
import torch.nn as nn

# 状态特征词表（与 SkillPolicy.state 的服务关键词对齐）
VOCAB = ["web", "ssh", "db", "ftp", "api", "flask", "java", "php", "go"]

# 分层动作头：常见状态 -> head 索引（其余归入 unknown）
# 扩展方式：policy.ensure_state("db") 动态注册新状态并追加动作头；
# 或直接在此添加映射（新增实例时生效）。
STATE_HEADS = {"": 0, "unknown": 0, "web": 1, "ssh": 2, "web+ssh": 3}


def state_key(fingerprint: str) -> str:
    """指纹 -> 规范化状态名（服务关键词排序拼接，如 "web+ssh"）。"""
    import re

    words = sorted(set(re.findall(r"[a-z]+", fingerprint.lower()))
                   & set(VOCAB))
    return "+".join(words)


def state_id(fingerprint: str) -> int:
    """指纹 -> 分层动作头索引（默认映射，含扩展状态时用实例级映射）。"""
    return STATE_HEADS.get(state_key(fingerprint),
                           STATE_HEADS["unknown"])


def state_feature(fingerprint: str) -> list[float]:
    """指纹 -> 多热向量。"""
    import re

    words = set(re.findall(r"[a-z]+", fingerprint.lower()))
    return [1.0 if v in words else 0.0 for v in VOCAB]


def feature_state(feat: list[float]) -> str:
    """多热向量 -> 规范化状态名（训练 rollouts 分组用）。"""
    words = [VOCAB[i] for i, v in enumerate(feat) if v > 0.5]
    return "+".join(words)


class ActorCritic(nn.Module):
    def __init__(self, n_feat: int, n_actions: int,
                 n_heads: int | None = None) -> None:
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(n_feat, 32), nn.ReLU())
        if n_heads is None:
            # 默认头数 = 最大已用索引 + 1（"" 与 "unknown" 共享索引 0）
            n_heads = max(STATE_HEADS.values()) + 1
        self.actor_heads = nn.ModuleList(
            [nn.Linear(32, n_actions) for _ in range(n_heads)])
        self.critic = nn.Linear(32, 1)

    def forward(self, x):
        """返回 (各状态头 logits 列表, critic 值)。"""
        h = self.shared(x)
        return [head(h) for head in self.actor_heads], self.critic(h)

    def add_head(self) -> int:
        """动态追加一个动作头，返回新头索引。"""
        self.actor_heads.append(
            nn.Linear(self.shared[0].out_features,
                      self.actor_heads[0].out_features))
        return len(self.actor_heads) - 1


class PPOSkillPolicy:
    """PPO 技能选择策略（分层动作头，可按需扩展）。"""

    def __init__(self, skill_ids: list[str], clip: float = 0.2,
                 lr: float = 3e-3) -> None:
        self.skill_ids = skill_ids
        self.n_actions = len(skill_ids)
        self.clip = clip
        self.state_heads = dict(STATE_HEADS)   # 实例级映射（扩展不污染默认集）
        self.model = ActorCritic(
            len(VOCAB), self.n_actions,
            n_heads=max(self.state_heads.values()) + 1)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)

    # ------------------------------------------------------------------
    def ensure_state(self, state_name: str) -> int:
        """注册新状态（自动追加动作头），返回 head 索引。

        配置驱动扩展：训练/评估中出现新状态组合（如 "db"、"web+db"）
        时自动加头；重复注册幂等。
        """
        if state_name not in self.state_heads:
            self.state_heads[state_name] = self.model.add_head()
        return self.state_heads[state_name]

    def _head_of(self, fingerprint: str) -> int:
        return self.state_heads.get(
            state_key(fingerprint), self.state_heads["unknown"])

    # ------------------------------------------------------------------
    def act(self, fingerprint: str, greedy: bool = False,
            rng: Optional[random.Random] = None) -> tuple[int, float]:
        """选择技能动作索引；返回 (action_idx, log_prob)。"""
        feat = torch.tensor([state_feature(fingerprint)], dtype=torch.float32)
        logits_all, _ = self.model(feat)
        logits = logits_all[self._head_of(fingerprint)]
        probs = torch.softmax(logits, dim=-1)
        if greedy:
            action = int(torch.argmax(probs))
            return action, float(torch.log(probs[0, action]).detach())
        dist = torch.distributions.Categorical(probs)
        action = int(dist.sample().item())
        return action, float(dist.log_prob(torch.tensor(action)).detach())

    def value(self, fingerprint: str) -> float:
        feat = torch.tensor([state_feature(fingerprint)], dtype=torch.float32)
        _, v = self.model(feat)
        return float(v.item())

    # ------------------------------------------------------------------
    def update(self, rollouts: list[dict], epochs: int = 4,
               gamma: float = 0.99, entropy_coef: float = 0.02,
               actor_weight: float = 1.0) -> float:
        """PPO 更新（per-state 归一化优势 + clip 目标 + 熵正则），返回平均损失。

        actor_weight=0 时仅训练 critic（价值网络预热：先拟合 V 再学策略，
        可显著降低优势噪声，提升小样本条件化稳定性）。
        """
        states = torch.tensor(
            [r["state"] for r in rollouts], dtype=torch.float32)
        actions = torch.tensor([r["action"] for r in rollouts])
        old_logps = torch.tensor([r["logp"] for r in rollouts])
        rewards = torch.tensor([r["reward"] for r in rollouts],
                               dtype=torch.float32)

        # 优势 = reward-to-go - V(s)（简化 GAE，λ=1 折现奖励）
        returns = []
        g = 0.0
        for r in reversed(rollouts):
            g = r["reward"] + gamma * g * (0 if r["done"] else 1)
            returns.insert(0, g)
        returns = torch.tensor(returns, dtype=torch.float32)
        _, values = self.model(states)
        advantages = (returns - values.squeeze(-1)).detach()
        # per-state 组内归一化：优势按状态分组计算，
        # 状态条件化信号不被跨状态奖励差异淹没
        # （如 web-only 成功 40 分 vs ssh-only 成功 60 分）
        import collections

        groups = collections.defaultdict(list)
        for i, r in enumerate(rollouts):
            groups[feature_state(r["state"])].append(i)
        adv_out = torch.zeros_like(advantages)
        for key, idxs in groups.items():
            adv = advantages[idxs]
            if adv.numel() > 1 and adv.std() > 1e-8:
                adv = (adv - adv.mean()) / (adv.std() + 1e-8)
            adv_out[idxs] = adv
        advantages = adv_out

        total_loss = 0.0
        # 训练前自动注册 rollouts 中出现的新状态（配置驱动扩展）
        for key in groups:
            self.ensure_state(key)
        for _ in range(epochs):
            # 各状态样本走各自的动作头（分层：互不串扰）
            _, values = self.model(states)
            actor_losses = []
            for key, idxs in groups.items():
                sid = self.state_heads[key]
                logits = self.model.actor_heads[sid](
                    self.model.shared(states[idxs]))
                probs = torch.softmax(logits, dim=-1)
                dist = torch.distributions.Categorical(probs)
                new_logps = dist.log_prob(actions[idxs])
                ratio = torch.exp(new_logps - old_logps[idxs])
                surr1 = ratio * advantages[idxs]
                surr2 = torch.clamp(ratio, 1 - self.clip,
                                    1 + self.clip) * advantages[idxs]
                actor_losses.append(-torch.min(surr1, surr2).mean())
            actor_loss = torch.stack(actor_losses).mean()
            critic_loss = nn.functional.mse_loss(
                values.squeeze(-1), returns)
            entropy = 0.0
            for key, idxs in groups.items():
                sid = self.state_heads[key]
                probs = torch.softmax(
                    self.model.actor_heads[sid](
                        self.model.shared(states[idxs])), dim=-1)
                entropy = entropy + torch.distributions.Categorical(
                    probs).entropy().mean()
            entropy = entropy / len(groups)   # 熵正则防策略崩溃
            loss = (actor_weight * actor_loss + 0.5 * critic_loss
                    - entropy_coef * entropy)
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            total_loss += float(loss.item())
        return total_loss / epochs

    # ------------------------------------------------------------------
    def best_skill(self, fingerprint: str) -> Optional[str]:
        idx, _ = self.act(fingerprint, greedy=True)
        return self.skill_ids[idx]

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model": self.model.state_dict(),
            "skill_ids": self.skill_ids,
            "state_heads": list(self.state_heads.keys()),  # 扩展头持久化
        }, p)
        return p

    @classmethod
    def load(cls, path: str | Path, skill_ids: Optional[list[str]] = None,
             **kwargs) -> "PPOSkillPolicy":
        data = torch.load(path, map_location="cpu")
        policy = cls(data["skill_ids"], **kwargs)
        # 按保存的映射重建扩展头（权重结构一致后再加载）
        for name in data.get("state_heads", []):
            policy.ensure_state(name)
        policy.model.load_state_dict(data["model"])
        return policy
