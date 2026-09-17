"""07 联动深化：XPentest 真实 LLM 决策在 07 仿真目标上跑分。

与 eval_evolution（序列模拟）不同，本脚本用真实 LLM 决策循环：
- 无技能版：PenAgent 从零决策（探索）
- 有技能版：技能注入后决策（按经验推进）
指标：完成任务所需 LLM 决策步数、成功率、LLM 调用次数。
运行：python examples/eval_evolution_llm.py（需 LLM 服务可用）
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G07 = ROOT.parent / "07-agent-war-range"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(G07))

from penagent.agent import PenAgent, Policy
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.memory import Memory, Skill
from penagent.tools import ToolRegistry, ToolSpec

from warfare.sim import Defense, Host, Service  # noqa: E402


def make_sim_host() -> Host:
    return Host(
        hostname="target-01",
        services=[
            Service(name="web", port=80, vulnerable=True, exploit="CVE-SQLI"),
            Service(name="ssh", port=22, vulnerable=True,
                    exploit="WEAK-PASSWD"),
        ],
        defense=Defense(ids_enabled=True, waf_enabled=False,
                        honeypot_enabled=False, response_time=1),
    )


def register_sim_tools(reg: ToolRegistry, host: Host) -> None:
    reg.register(ToolSpec(
        name="port_scan", description="TCP 端口扫描（被动侦察）",
        parameters={"host": {"type": "string"},
                    "ports": {"type": "string"}},
        fn=lambda **kw: {"open_ports": [s.port for s in host.services]}))
    reg.register(ToolSpec(
        name="http_probe", description="HTTP 探测（被动）",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"server": "demo-web", "title": "Demo Portal"}))
    reg.register(ToolSpec(
        name="robots_fetch", description="robots 抓取（被动）",
        parameters={"base_url": {"type": "string"}},
        fn=lambda **kw: {"disallow": ["/admin"]}))
    reg.register(ToolSpec(
        name="exploit_web", description="Web 漏洞利用（危险）",
        parameters={"url": {"type": "string"}}, dangerous=True,
        fn=lambda **kw: _exploit(host, "web")))
    reg.register(ToolSpec(
        name="exploit_ssh", description="SSH 弱口令利用（危险）",
        parameters={"url": {"type": "string"}}, dangerous=True,
        fn=lambda **kw: _exploit(host, "ssh")))


def _exploit(host: Host, name: str) -> dict:
    svc = host.service_by_name(name)
    if svc and svc.vulnerable:
        svc.compromised = True
        return {"compromised": True, "service": name}
    return {"compromised": False}


RECON_SKILL = Skill(
    id="recon-web", title="Web 服务侦察与漏洞利用",
    target_fingerprint="web service flask python",
    steps=["port_scan 识别开放端口", "http_probe 确认 Web 框架",
           "exploit_web 利用 Web 漏洞"],
    tools=["port_scan", "http_probe", "exploit_web"],
    evidence_refs=[1, 2, 3],
)


def run_task(reg: ToolRegistry, mem: Memory, ev: EvidenceChain,
             objective: str, authorize: bool, host: Host,
             mock: bool = False, mock_seq: tuple = ()) -> dict:
    if not mock:
        agent = PenAgent(reg, mem, ev, LLMConfig(timeout=300),
                         Policy(authorize=authorize), max_steps=8)
        result = agent.run("http://127.0.0.1:8080", objective,
                           fingerprint="127.0.0.1 web service")
        return {"outcome": result.outcome, "steps": result.steps,
                "summary": result.summary,
                "injected": result.injected_skills}
    # mock 模式：确定性决策序列（LLM 服务不可用时的降级演示）
    steps = 0
    for tool in mock_seq:
        steps += 1
        reg.execute(tool, {"host": "127.0.0.1", "url": "http://x"})
        if host.service_by_name("web").compromised:
            return {"outcome": "success", "steps": steps,
                    "summary": "mock 决策达成", "injected": []}
    return {"outcome": "failed", "steps": steps, "summary": "mock 未达成",
            "injected": []}


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true",
                    help="mock 决策模式（LLM 服务不可用时）")
    args = ap.parse_args()
    shutil.rmtree(ROOT / "data" / "evol-llm", ignore_errors=True)
    print("=" * 64)
    print("07 联动深化：真实 LLM 决策进化评测"
          + ("（mock 降级）" if args.mock else "（真实 LLM，每轮需调用）"))
    print("=" * 64)

    def _round(skilled: bool):
        host = make_sim_host()
        reg = ToolRegistry()
        register_sim_tools(reg, host)
        mem = Memory(ROOT / "data" / "evol-llm"
                     / ("skilled" if skilled else "naive"))
        if skilled:
            mem.add_skill(RECON_SKILL)
        ev = EvidenceChain(ROOT / "data" / "evol-llm"
                           / ("skilled" if skilled else "naive")
                           / "chain.jsonl")
        if args.mock:
            seq = (["port_scan", "http_probe", "exploit_web"]
                   if skilled else
                   ["robots_fetch", "http_probe", "port_scan",
                    "exploit_ssh", "exploit_web"])
        else:
            seq = ()
        r = run_task(reg, mem, ev, "侦察并尝试利用 Web 服务漏洞", True,
                     host, mock=args.mock, mock_seq=seq)
        ok = r["outcome"] == "success" and \
            host.service_by_name("web").compromised
        tag = "有技能" if skilled else "无技能"
        print(f"  [{tag}] outcome={r['outcome']} steps={r['steps']} "
              f"目标达成={ok} 注入技能={len(r['injected'])}")
        return {"steps": r["steps"], "ok": ok}

    naive = [_round(False)]
    skilled = [_round(True)]

    n_steps = [s["steps"] for s in naive if s["ok"]]
    s_steps = [s["steps"] for s in skilled if s["ok"]]
    print(f"\n无技能：成功 {sum(1 for s in naive if s['ok'])}/2，"
          f"成功平均步数 {sum(n_steps) / len(n_steps) if n_steps else '-'}")
    print(f"有技能：成功 {sum(1 for s in skilled if s['ok'])}/2，"
          f"成功平均步数 {sum(s_steps) / len(s_steps) if s_steps else '-'}")
    if n_steps and s_steps:
        ratio = (sum(s_steps) / len(s_steps)) / (sum(n_steps) / len(n_steps))
        print(f"决策步数变化 {1 - ratio:.0%}")
    shutil.rmtree(ROOT / "data" / "evol-llm", ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
