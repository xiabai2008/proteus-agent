"""闭环回归评测：进化各层叠加收益量化（07 仿真）。

同一组随机目标上对比四种决策策略：
  1. 基线     ：无技能、固定探索序列
  2. +技能    ：技能池直接选择（full-recon 固定链）
  3. +Q学习   ：Q-learning 训练后按状态选最优技能
  4. +PPO     ：神经网络策略训练后 argmax
指标：成功率、平均决策步数、相对基线收益。

运行：python examples/eval_closed_loop.py
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


def target_set(n: int = 30, seed: int = 99) -> list:
    """固定种子生成评测目标集（四种策略同一组目标，保证可比）。"""
    rng = random.Random(seed)
    hosts = []
    for _ in range(n):
        hosts.append(make_host(rng))
    return hosts


def evaluate(hosts, choose_seq, fallback: bool = False) -> dict:
    """对目标集执行（每目标深拷贝，防状态污染）。

    fallback=True：策略序列失败后补执行 full-recon 兜底（稳健性优化），
    累计步数。
    """
    import copy

    steps, ok = [], []
    for host in hosts:
        h = copy.deepcopy(host)   # 独立副本：exploit 状态不跨策略泄漏
        seq = choose_seq(h)
        s, success = execute_episode(h, seq)
        if not success and fallback:
            extra, success = execute_episode(h, SKILLS["full-recon"][1])
            s += extra
        steps.append(s if success else None)
        ok.append(success)
    win = [s for s in steps if s is not None]
    return {"success_rate": sum(ok) / len(ok),
            "avg_steps": (sum(win) / len(win)) if win else None}


def train_and_evaluate(*, seed: int = 42) -> list[dict]:
    """训练 Q 学习与 PPO，在固定目标集上评估全部策略。

    返回每策略一条结构化记录（供 main() 打印与评测骨架消费）：
      [{"name", "success_rate", "avg_steps", "gain_vs_baseline"}, ...]
    第一条是基线，其余相对它计算收益。需 torch（PPO 层）——调用方负责
    处理 ModuleNotFoundError。
    """
    import torch

    torch.manual_seed(seed)
    rng = random.Random(seed)

    # 训练 Q-learning（状态均衡采样）
    ql = SkillPolicy(epsilon=0.3)
    for _ in range(40):
        for state in TRAIN_STATES:
            host = make_host_state(rng, state)
            fp = " ".join(s.name for s in host.services)
            action = ql.choose(SkillPolicy.state(fp), SKILL_IDS, rng)
            s, success = execute_episode(host, SKILLS[action][1])
            ql.update(SkillPolicy.state(fp), action, reward(s, success),
                      SkillPolicy.state(fp))

    # 训练 PPO（状态均衡采样：400 rollouts，10 批 × 40 轮）
    ppo = PPOSkillPolicy(SKILL_IDS, lr=3e-3)
    for _batch in range(10):
        rollouts = []
        for state in TRAIN_STATES:
            for _ in range(10):
                host = make_host_state(rng, state)
                fp = " ".join(s.name for s in host.services)
                action, logp = ppo.act(fp)
                s, success = execute_episode(host, SKILLS[SKILL_IDS[action]][1])
                rollouts.append({"state": state_feature(fp), "action": action,
                                 "logp": logp, "reward": reward(s, success),
                                 "done": True})
        ppo.update(rollouts, epochs=4)

    hosts = target_set()

    def _by_policy(policy, fallback: bool = False) -> dict:
        """按策略选择技能序列评估（best_skill 只查一次）。"""
        def choose(h):
            fp = " ".join(s.name for s in h.services)
            best = policy.best_skill(fp)
            return SKILLS[best][1] if best else EXPLORE_SEQ[:]
        return evaluate(hosts, choose, fallback=fallback)

    baseline = evaluate(hosts, lambda h: EXPLORE_SEQ[:])
    rows = [
        ("基线(无技能)", baseline),
        ("+技能(直接)", evaluate(hosts, lambda h: SKILLS["full-recon"][1])),
        ("+Q学习", _by_policy(ql)),
        ("+PPO", _by_policy(ppo)),
        ("+Q学习(兜底)", _by_policy(ql, fallback=True)),
        ("+PPO(兜底)", _by_policy(ppo, fallback=True)),
    ]
    b_steps = baseline["avg_steps"]
    out = []
    for name, r in rows:
        gain = ((b_steps - r["avg_steps"]) / b_steps
                if r["avg_steps"] and b_steps else 0.0)
        out.append({"name": name, "success_rate": r["success_rate"],
                    "avg_steps": r["avg_steps"], "gain_vs_baseline": gain})
    return out


def main() -> int:
    try:
        import torch  # noqa: F401
    except ModuleNotFoundError:
        print("闭环评测含 PPO 层，需要 torch（可选依赖）。"
              "安装：pip install torch --index-url https://download.pytorch.org/whl/cpu")
        return 2

    print("=" * 64)
    print("闭环回归评测：进化各层叠加收益（07 仿真，30 目标）")
    print("=" * 64)
    rows = train_and_evaluate()

    print(f"\n{'策略':<16}{'成功率':>8}{'平均步数':>10}{'收益(步数)':>10}")
    for r in rows:
        gain = r["gain_vs_baseline"]
        print(f"{r['name']:<16}{r['success_rate']:>7.0%}"
              f"{r['avg_steps']:>10.2f}"
              f"{(f'-{gain:.0%}' if gain >= 0 else f'+{-gain:.0%}'):>10}")

    print("\n进化收益链：每层相对基线")
    for r in rows[1:]:
        print(f"  {r['name']:<16}步数下降 {r['gain_vs_baseline']:.0%}"
              f"（成功率 {r['success_rate']:.0%}）")
    shutil.rmtree(ROOT / "data" / "closedloop", ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
