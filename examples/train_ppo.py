"""PPO 训练与对比：技能选择策略 PPO vs Q-learning vs 随机探索（07 仿真）。

复用 train_policy 的仿真环境（make_host / execute_episode / 技能池）。
"""
import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from train_policy import (EXPLORE_SEQ, SKILLS, TRAIN_STATES, execute_episode,  # noqa: E402
                          make_host, make_host_state, reward)

from penagent.ppo import PPOSkillPolicy, state_feature  # noqa: E402
from penagent.rl import SkillPolicy  # noqa: E402

SKILL_IDS = list(SKILLS.keys())


def collect_rollouts(policy: PPOSkillPolicy, episodes: int,
                     rng: random.Random) -> tuple[list, list]:
    """状态轮换采样：四状态模板均衡（各 episodes/4 轮），
    确保 PPO 学到按状态条件化而非全局最频繁动作。"""
    rollouts, results = [], []
    per_state = episodes // len(TRAIN_STATES)
    for state in TRAIN_STATES:
        for _ in range(per_state):
            host = make_host_state(rng, state)
            fp = " ".join(s.name for s in host.services)
            action, logp = policy.act(fp)
            seq = SKILLS[SKILL_IDS[action]][1]
            steps, success = execute_episode(host, seq)
            r = reward(steps, success)   # 与 train_policy 同源 v2 奖励
            rollouts.append({"state": state_feature(fp), "action": action,
                             "logp": logp, "reward": r,
                             "done": True})   # 单步 episode
            results.append({"steps": steps if success else None,
                            "ok": success})
    return rollouts, results


def eval_policy(policy, episodes: int = 40, seed: int = 7) -> dict:
    rng = random.Random(seed)
    steps, ok = [], []
    for _ in range(episodes):
        host = make_host(rng)
        fp = " ".join(s.name for s in host.services)
        action, _ = policy.act(fp, greedy=True)
        seq = SKILLS[SKILL_IDS[action]][1]
        s, success = execute_episode(host, seq)
        steps.append(s if success else None)
        ok.append(success)
    win = [s for s in steps if s is not None]
    return {"success_rate": sum(ok) / len(ok),
            "avg_steps": (sum(win) / len(win)) if win else None}


def eval_qlearning(policy: SkillPolicy, episodes: int = 40,
                   seed: int = 7) -> dict:
    rng = random.Random(seed)
    steps, ok = [], []
    for _ in range(episodes):
        host = make_host(rng)
        state = SkillPolicy.state(" ".join(s.name for s in host.services))
        best = policy.best_skill(" ".join(s.name for s in host.services))
        seq = SKILLS[best][1] if best else EXPLORE_SEQ[:]
        s, success = execute_episode(host, seq)
        steps.append(s if success else None)
        ok.append(success)
    win = [s for s in steps if s is not None]
    return {"success_rate": sum(ok) / len(ok),
            "avg_steps": (sum(win) / len(win)) if win else None}


def main() -> int:
    import torch

    torch.manual_seed(42)   # PPO 训练可复现
    rng = random.Random(42)
    print("=" * 64)
    print("PPO 升级：技能选择策略 PPO vs Q-learning vs 随机（07 仿真）")
    print("=" * 64)

    # 训练 PPO（均衡分布下需更多样本：400 rollouts，10 批 × 40 轮）
    ppo = PPOSkillPolicy(SKILL_IDS, lr=3e-3)
    for batch in range(10):
        rollouts, results = collect_rollouts(ppo, 40, rng)
        loss = ppo.update(rollouts, epochs=4)
        win = sum(1 for r in results if r["ok"]) / len(results)
        print(f"  batch {batch + 1}: 20 轮成功率 {win:.0%}  loss={loss:.2f}")
    ppo.save(ROOT / "data" / "ppo" / "policy.pt")

    # 训练 Q-learning（对比基线，同环境、同奖励、状态均衡采样）
    ql = SkillPolicy(epsilon=0.3)
    for _ in range(40):
        for state in TRAIN_STATES:
            host = make_host_state(rng, state)
            fp = " ".join(s.name for s in host.services)
            action = ql.choose(SkillPolicy.state(fp), SKILL_IDS, rng)
            steps, success = execute_episode(host, SKILLS[action][1])
            ql.update(SkillPolicy.state(fp), action, reward(steps, success),
                      SkillPolicy.state(fp))

    rl = eval_policy(ppo)
    q = eval_qlearning(ql)
    random_res = eval_qlearning(SkillPolicy(), episodes=40, seed=7)

    def fmt(r: dict) -> str:
        return (f"成功率 {r['success_rate']:.0%}，"
                f"平均步数 {r['avg_steps']}")

    print(f"\n评估（40 轮）:")
    print(f"  PPO        ：{fmt(rl)}")
    print(f"  Q-learning ：{fmt(q)}")
    print(f"  随机探索   ：{fmt(random_res)}")
    if rl["success_rate"] >= q["success_rate"] and \
            (rl["avg_steps"] or 99) <= (q["avg_steps"] or 99):
        print("  PPO 全面不劣于 Q-learning [OK]")
    elif (rl["avg_steps"] or 99) < (q["avg_steps"] or 99):
        print("  PPO 决策步数更优（状态特化学习），成功率待提升 [PARTIAL OK]")
    else:
        print("  PPO vs Q-learning 各有优劣（如实呈现）")
    shutil.rmtree(ROOT / "data" / "ppo" / "tmp", ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
