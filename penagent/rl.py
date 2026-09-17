"""RL 策略进化：ε-greedy Q-learning 训练"技能选择策略"。

- 状态：目标指纹（服务组合，如 web/ssh/db）
- 动作：选择沉淀技能（或探索工具序列）
- 奖励：任务成功 +100-步数惩罚；失败 -50-步数惩罚
- 训练环境：07 仿真目标（Host 随机生成）
- 输出：Q 表（JSON 持久化），推理时按状态选择最优技能注入 PenAgent

与 quantum-rl-scheduler 的思路衔接：迁移优先级/技能选择建模为
顺序决策问题；本实现为轻量 Q-learning（PPO/MAPPO 可后续替换）。
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Optional


class SkillPolicy:
    """技能选择策略（表格 Q-learning + ε-greedy）。"""

    def __init__(self, epsilon: float = 0.2, alpha: float = 0.1,
                 gamma: float = 0.9) -> None:
        self.epsilon = epsilon
        self.alpha = alpha
        self.gamma = gamma
        self.q: dict[str, dict[str, float]] = {}

    # ------------------------------------------------------------------
    @staticmethod
    def state(fingerprint: str) -> str:
        """指纹离散化：提取服务关键词排序拼接。"""
        import re

        words = sorted({w for w in re.findall(r"[a-z]+", fingerprint.lower())
                        if w in ("web", "ssh", "db", "ftp", "api",
                                 "flask", "java", "php")})
        return "+".join(words) or "unknown"

    def choose(self, state: str, skills: list,
               rng: Optional[random.Random] = None) -> str:
        """ε-greedy 选技能：返回技能 id（ε 概率随机选，否则 argmax）。"""
        rng = rng or random
        if rng.random() < self.epsilon and skills:
            return rng.choice(list(skills))
        values = self.q.get(state, {})
        if not values:
            return rng.choice(list(skills)) if skills else "explore"
        return max(values, key=values.get)

    def update(self, state: str, action: str, reward: float,
               next_state: str) -> None:
        """Q(s,a) <- Q + α(r + γ·max Q(s',a') - Q)。"""
        table = self.q.setdefault(state, {})
        old = table.get(action, 0.0)
        future = max(self.q.get(next_state, {}).values(), default=0.0)
        table[action] = old + self.alpha * (
            reward + self.gamma * future - old)

    # ------------------------------------------------------------------
    def best_skill(self, fingerprint: str) -> Optional[str]:
        """按目标指纹返回最优技能 id（内部离散化状态）。"""
        state = self.state(fingerprint)
        values = self.q.get(state, {})
        if not values:
            return None
        return max(values, key=values.get)

    def summary(self) -> dict:
        return {
            "states": len(self.q),
            "q_table": {s: dict(sorted(v.items(), key=lambda x: -x[1]))
                        for s, v in self.q.items()},
        }

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.summary(), ensure_ascii=False, indent=2),
                     encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path, **kwargs) -> "SkillPolicy":
        p = Path(path)
        policy = cls(**kwargs)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            for s, items in (data.get("q_table") or {}).items():
                policy.q[s] = {a: float(v) for a, v in items.items()}
        return policy
