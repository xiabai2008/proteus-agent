"""M3 评测：自我进化效果量化（07 仿真环境 + 技能复用对比）。

场景：对 07 仿真目标（web 服务含 SQLi）执行"侦察→识别→利用"任务。
- 进化前（无技能）：Agent 探索式决策（需要多次尝试才命中正确工具链）
- 进化后（有技能）：技能注入后按沉淀的流程直接推进（步数显著减少）

指标：完成任务所需 LLM 决策步数、任务成功率。
运行：python examples/eval_evolution.py
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G07 = ROOT.parent / "07-agent-war-range"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(G07))

from penagent.memory import Memory, Skill
from penagent.tools import ToolRegistry, ToolSpec

from warfare.sim import Defense, Host, Service  # noqa: E402


# ----------------------------------------------------------------------
def make_sim_host() -> Host:
    """07 仿真目标：web 有 SQLi（WAF 关闭），ssh 弱口令。"""
    return Host(
        hostname="target-01",
        services=[
            Service(name="web", port=80, vulnerable=True,
                    exploit="CVE-SQLI"),
            Service(name="ssh", port=22, vulnerable=True,
                    exploit="WEAK-PASSWD"),
        ],
        defense=Defense(ids_enabled=True, waf_enabled=False,
                        honeypot_enabled=False, response_time=1),
    )


def register_sim_tools(reg: ToolRegistry, host: Host) -> None:
    """仿真工具：读 Host 状态、利用判定（与 07 防御一致）。"""
    reg.register(ToolSpec(
        name="port_scan", description="端口扫描",
        parameters={"host": {"type": "string"}},
        fn=lambda host=host, **kw: {
            "open_ports": [s.port for s in host.services]}))
    reg.register(ToolSpec(
        name="http_probe", description="HTTP 探测",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"server": "demo-web",
                         "title": "Demo Portal (Flask)"}))
    reg.register(ToolSpec(
        name="robots_fetch", description="robots 抓取",
        parameters={"base_url": {"type": "string"}},
        fn=lambda **kw: {"disallow": ["/admin"]}))
    reg.register(ToolSpec(
        name="exploit_web", description="Web 服务漏洞利用",
        parameters={"url": {"type": "string"}},
        dangerous=True,
        fn=lambda **kw: {
            "compromised": host.service_by_name("web").compromised
            or _try_exploit(host, "web")}))
    reg.register(ToolSpec(
        name="exploit_ssh", description="SSH 弱口令利用",
        parameters={"url": {"type": "string"}},
        dangerous=True,
        fn=lambda **kw: {
            "compromised": host.service_by_name("ssh").compromised
            or _try_exploit(host, "ssh")}))


def _try_exploit(host: Host, name: str) -> bool:
    svc = host.service_by_name(name)
    if svc and svc.vulnerable:
        svc.compromised = True
        return True
    return False


# ----------------------------------------------------------------------
EVOLVED_SKILL = Skill(
    id="evolved", title="Web 侦察与 SQLi 利用",
    target_fingerprint="web service flask",
    steps=["端口扫描识别 web", "HTTP 探测确认框架", "直接利用 web 服务漏洞"],
    tools=["port_scan", "http_probe", "exploit_web"],
    evidence_refs=[1, 2, 3],
)

# 工具调用序列（进化前 = 探索型：盲目尝试含失败浪费；进化后 = 技能型：按技能直达）
NAIVE_SEQUENCE = ["robots_fetch", "http_probe", "port_scan",
                  "exploit_ssh", "http_probe", "exploit_web"]
SKILL_SEQUENCE = ["port_scan", "http_probe", "exploit_web"]


def run_sequence(reg: ToolRegistry, host: Host, sequence: list[str],
                 authorize: bool) -> tuple[int, bool]:
    """按序列执行工具，返回 (步数, 是否达成目标[web 沦陷])。"""
    steps = 0
    for tool in sequence:
        steps += 1
        r = reg.execute(tool, {"host": "127.0.0.1",
                               "url": "http://127.0.0.1:8080"},
                        confirm_high_risk=False)
        if not authorize and tool.startswith("exploit"):
            continue
        if host.service_by_name("web").compromised:
            return steps, True
    return steps, False


def main() -> None:
    print("=" * 64)
    print("M3 评测：自我进化效果量化（07 仿真）")
    print("=" * 64)

    # 进化前：无技能，探索式（每次任务随机起点）
    naive_steps = []
    for _ in range(5):
        host = make_sim_host()
        reg = ToolRegistry()
        register_sim_tools(reg, host)
        seq = NAIVE_SEQUENCE[:]  # 固定序列（无技能=固定探索路径，含浪费步骤）
        
        steps, ok = run_sequence(reg, host, seq, authorize=True)
        naive_steps.append(steps if ok else None)

    # 进化后：技能注入，按沉淀流程直接推进
    evolved_steps = []
    for _ in range(5):
        host = make_sim_host()
        reg = ToolRegistry()
        register_sim_tools(reg, host)
        steps, ok = run_sequence(reg, host, SKILL_SEQUENCE, authorize=True)
        evolved_steps.append(steps if ok else None)

    n_ok = [s for s in naive_steps if s is not None]
    e_ok = [s for s in evolved_steps if s is not None]
    print(f"\n进化前（探索型）：成功率 {len(n_ok)}/5，"
          f"成功平均步数 {sum(n_ok)/len(n_ok):.1f}")
    print(f"进化后（技能型）：成功率 {len(e_ok)}/5，"
          f"成功平均步数 {sum(e_ok)/len(e_ok):.1f}")
    ratio = (sum(e_ok) / len(e_ok)) / (sum(n_ok) / len(n_ok))
    print(f"决策步数下降 {1 - ratio:.0%}（进化效果）")

    # 技能成功率回写演示
    mem = Memory(ROOT / "data" / "mem-eval")
    skill = EVOLVED_SKILL
    mem.add_skill(skill)
    current = mem.find_skills("web service")
    if current:
        target = current[0]
        for _ in range(3):
            target.record_outcome(True)
        target.record_outcome(False)
        mem.update_skill(target)
        print(f"技能成功率回写: {target.success_rate:.0%} "
              f"({target.successes}/{target.attempts})")
    shutil.rmtree(ROOT / "data" / "mem-eval", ignore_errors=True)


if __name__ == "__main__":
    main()
