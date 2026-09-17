"""RL 策略进化训练：在 07 仿真上训练技能选择策略并验证收敛。

- 仿真：每轮随机生成目标（web/ssh 有/无漏洞组合，指纹=服务组合）
- 技能池：web 侦察利用 / ssh 弱口令 / 综合探索
- 训练：ε-greedy Q-learning 迭代 → Q 表
- 评估：训练后固定策略（ε=0）vs 随机策略，对比成功率与平均步数

运行：python examples/train_policy.py
"""
import random
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G07 = ROOT.parent / "07-agent-war-range"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(G07))

from penagent.rl import SkillPolicy

from warfare.sim import Defense, Host, Service  # noqa: E402

# 技能池：id -> (指纹关键词, 工具序列)
SKILLS = {
    "web-exploit": ("web", ["port_scan", "http_probe", "exploit_web"]),
    "ssh-exploit": ("ssh", ["port_scan", "exploit_ssh"]),
    "full-recon": ("unknown", ["port_scan", "http_probe", "robots_fetch",
                               "exploit_web", "exploit_ssh"]),
}
EXPLORE_SEQ = ["robots_fetch", "http_probe", "port_scan", "exploit_ssh",
               "exploit_web"]


def make_host(rng: random.Random) -> Host:
    """随机生成仿真目标（web/ssh 服务组合均衡 + 状态内高漏洞率）。

    v2 平衡分布：
    - 服务出现率各 0.5（web-only/ssh-only/web+ssh/none 四状态各 ~25%）；
    - 服务出现后漏洞率 0.95（状态主服务短链期望最优）。
    """
    services = []
    if rng.random() < 0.5:
        vulnerable = rng.random() < 0.95
        services.append(Service(name="web", port=80, vulnerable=vulnerable,
                                exploit="CVE-SQLI"))
    if rng.random() < 0.5:
        vulnerable = rng.random() < 0.95
        services.append(Service(name="ssh", port=22, vulnerable=vulnerable,
                                exploit="WEAK-PASSWD"))
    return Host(hostname="target-x", services=services,
                defense=Defense(ids_enabled=True, waf_enabled=False,
                                honeypot_enabled=False))


def make_host_state(rng: random.Random, state: str) -> Host:
    """按指定状态模板生成目标（训练状态均衡轮换采样）。

    state：""(none) / "web" / "ssh" / "web+ssh"；服务出现后漏洞率 0.95。
    """
    services = []
    for name in (state.split("+") if state else []):
        vulnerable = rng.random() < 0.95
        services.append(Service(name=name, port=80 if name == "web" else 22,
                                vulnerable=vulnerable,
                                exploit="CVE-SQLI" if name == "web"
                                else "WEAK-PASSWD"))
    return Host(hostname="target-x", services=services,
                defense=Defense(ids_enabled=True, waf_enabled=False,
                                honeypot_enabled=False))


# 训练状态轮换模板（四状态均衡：每模板同轮数）
TRAIN_STATES = ["", "web", "ssh", "web+ssh"]


def fingerprint(host: Host) -> str:
    svcs = [s.name for s in host.services]
    return " ".join(svcs)


def register_tools(reg, host: Host) -> None:
    from penagent.tools import ToolSpec

    reg.register(ToolSpec(
        name="port_scan", description="端口扫描",
        parameters={"host": {"type": "string"}},
        fn=lambda **kw: {"open_ports": [s.port for s in host.services]}))
    reg.register(ToolSpec(
        name="http_probe", description="HTTP 探测",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"server": "demo", "title": "Demo"}))
    reg.register(ToolSpec(
        name="robots_fetch", description="robots 抓取",
        parameters={"base_url": {"type": "string"}},
        fn=lambda **kw: {"disallow": []}))
    reg.register(ToolSpec(
        name="exploit_web", description="Web 利用",
        parameters={"url": {"type": "string"}}, dangerous=True,
        fn=lambda **kw: _exp(host, "web")))
    reg.register(ToolSpec(
        name="exploit_ssh", description="SSH 利用",
        parameters={"url": {"type": "string"}}, dangerous=True,
        fn=lambda **kw: _exp(host, "ssh")))


def _exp(host: Host, name: str) -> dict:
    svc = host.service_by_name(name)
    if svc and svc.vulnerable:
        svc.compromised = True
        return {"compromised": True}
    return {"compromised": False}


def execute_episode(host: Host, seq: list[str]) -> tuple[int, bool]:
    """执行工具序列，返回 (步数, 是否达成[任一漏洞服务沦陷])。"""
    from penagent.tools import ToolRegistry

    reg = ToolRegistry()
    register_tools(reg, host)
    steps = 0
    for tool in seq:
        steps += 1
        reg.execute(tool, {"host": "127.0.0.1", "url": "http://x"})
        if any(s.compromised for s in host.services):
            return steps, True
    return steps, False


def reward(steps: int, success: bool) -> float:
    """v2 加权奖励：强失败惩罚（稳健导向）+ 重步数惩罚（效率导向）。

    成功 100-20·steps（ssh-exploit 2 步=60、web-exploit 3 步=40）；
    失败 -80-5·steps。
    """
    return 100 - 20 * steps if success else -80 - 5 * steps


def train(episodes: int = 60, seed: int = 42) -> SkillPolicy:
    rng = random.Random(seed)
    policy = SkillPolicy(epsilon=0.3)
    history = []

    for ep in range(1, episodes + 1):
        host = make_host(rng)
        state = SkillPolicy.state(fingerprint(host))
        action = policy.choose(state, list(SKILLS), rng)
        seq = SKILLS[action][1]
        steps, success = execute_episode(host, seq)
        r = reward(steps, success)
        next_host = make_host(rng)
        policy.update(state, action, r, SkillPolicy.state(
            fingerprint(next_host)))
        history.append(success)
        if ep % 20 == 0:
            win = sum(history[-20:]) / 20
            print(f"  epoch {ep:>3}: 近 20 轮成功率 {win:.0%}  "
                  f"Q 状态 {len(policy.q)}")
    return policy, history


def evaluate(policy: SkillPolicy, episodes: int = 20,
             seed: int = 7, greedy: bool = True) -> dict:
    """评估：greedy(ε=0 用最优技能) vs 随机探索。"""
    rng = random.Random(seed)
    steps, ok = [], []
    for _ in range(episodes):
        host = make_host(rng)
        state = SkillPolicy.state(fingerprint(host))
        if greedy:
            best = policy.best_skill(" ".join(s.name for s in host.services))
            seq = SKILLS[best][1] if best else EXPLORE_SEQ[:]
        else:
            seq = EXPLORE_SEQ[:]   # 固定探索序列（无策略盲目尝试）
        s, success = execute_episode(host, seq)
        steps.append(s if success else None)
        ok.append(success)
    win = [s for s in steps if s is not None]
    return {"success_rate": sum(ok) / len(ok),
            "avg_steps": (sum(win) / len(win)) if win else None}


def main() -> None:
    print("=" * 64)
    print("RL 策略进化：ε-greedy Q-learning 训练技能选择策略（07 仿真）")
    print("=" * 64)
    policy, history = train(episodes=120)
    policy.save(ROOT / "data" / "rl" / "policy.json")

    rl = evaluate(policy, greedy=True)
    naive = evaluate(policy, greedy=False)
    print(f"\n评估（20 轮）:")
    print(f"  RL 策略（ε=0）：成功率 {rl['success_rate']:.0%}，"
          f"平均步数 {rl['avg_steps']}")
    print(f"  随机探索      ：成功率 {naive['success_rate']:.0%}，"
          f"平均步数 {naive['avg_steps']}")
    if rl["success_rate"] >= naive["success_rate"]:
        print("  RL 策略优于/不低于随机探索 [OK]（技能选择策略已进化）")
    print(f"\nQ 表摘要: {policy.summary()['q_table']}")
    shutil.rmtree(ROOT / "data" / "rl" / "episodes", ignore_errors=True)


if __name__ == "__main__":
    main()
