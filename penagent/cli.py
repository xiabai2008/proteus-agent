"""CLI 入口：pentest 命令。

用法示例：
  pentest run --target http://127.0.0.1:8080 --objective "侦察并总结目标"
  pentest run --target ... --authorize          # 允许危险工具
  pentest reflect <mission_id>                  # 任务后反思（LLM 复盘）
  pentest skills / missions / agents / verify
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from penagent.agent import PenAgent, Policy
from penagent.builtin_tools import register_builtins
from penagent.evidence import EvidenceChain
from penagent.external_tools import load_external_tools
from penagent.llm import LLMConfig
from penagent.memory import Memory
from penagent.tools import ToolRegistry


def _make_agent(args, registry=None, memory=None, evidence=None):
    reg = registry or ToolRegistry()
    register_builtins(reg)
    load_external_tools(reg)
    from penagent.adapters.packetforge import register_packetforge
    from penagent.adapters.rayscan import register_rayscan

    register_packetforge(reg)
    register_rayscan(reg)
    mem = memory or Memory(args.data)
    ev = evidence or EvidenceChain(Path(args.data) / "chain.jsonl")
    policy = Policy(allowed_targets=args.targets or None,
                    authorize=args.authorize)
    skill_policy = None
    if getattr(args, "rl_policy", "") and Path(args.rl_policy).exists():
        path = args.rl_policy
        if path.endswith(".pt"):
            from penagent.ppo import PPOSkillPolicy

            skill_policy = PPOSkillPolicy.load(path)
            print(f"PPO 策略已加载: {path}")
        else:
            from penagent.rl import SkillPolicy

            skill_policy = SkillPolicy.load(path)
            print(f"Q-learning 策略已加载: {path}"
                  f"（{len(skill_policy.q)} 个状态）")
    return PenAgent(reg, mem, ev, LLMConfig.from_env(), policy,
                    max_steps=args.max_steps, skill_policy=skill_policy)


def _auto_fingerprint(target: str) -> str:
    """目标指纹自动推导：host + 服务类型（M2 技能复用匹配）。"""
    import urllib.parse

    if target.startswith(("http://", "https://")):
        host = urllib.parse.urlparse(target).hostname or ""
        return f"{host} web service"
    host = target.split("/")[0].split(":")[0]
    return host


def cmd_run(args) -> int:
    agent = _make_agent(args)
    fingerprint = args.fp or _auto_fingerprint(args.target)
    print(f"目标: {args.target}  任务: {args.objective}")
    print(f"目标指纹: {fingerprint}")
    if args.authorize:
        print("[提示] 危险工具已授权（仅用于授权目标）")
    result = agent.run(args.target, args.objective, fingerprint=fingerprint,
                       stealth=args.stealth)
    print(f"\n任务结果: {result.outcome}（步骤 {result.steps}）")
    if result.injected_skills:
        print(f"记忆复用: 注入 {len(result.injected_skills)} 条历史技能"
              f"（{result.injected_skills}）")
    else:
        print("记忆复用: 无匹配技能（首次任务）")
    if args.stealth:
        print("[对抗模式] 技能按隐蔽优先排序（exposure 低者在前）")
    print(f"总结: {result.summary}")
    print(f"证据引用: seq={result.evidence_refs}")
    print(f"作战记录: data/missions/{result.mission_id}.json")
    return 0


def cmd_reflect(args) -> int:
    from penagent.reflect import Reflector

    memory = Memory(args.data)
    evidence = EvidenceChain(Path(args.data) / "chain.jsonl")
    analysis, skill = Reflector().reflect(args.mission, memory, evidence)
    print(f"反思: {analysis}")
    if skill:
        print(f"技能已沉淀: {skill.title} "
              f"(指纹: {skill.target_fingerprint}, "
              f"证据: seq={skill.evidence_refs})")
    return 0


def cmd_agents(args) -> int:
    reg = ToolRegistry()
    register_builtins(reg)
    info = load_external_tools(reg)
    from penagent.adapters.packetforge import register_packetforge
    from penagent.adapters.rayscan import register_rayscan

    pf_info = register_packetforge(reg)
    rs_info = register_rayscan(reg)
    print(f"内置工具 {len(reg.names())} 个:")
    for name in reg.names():
        spec = reg.get(name)
        danger = " [高危]" if spec.dangerous else ""
        print(f"  {name:<18} [{spec.kind}]{danger} {spec.description}")
    print(f"\n外部工具加载: {info}")
    print(f"PacketForge 接入: {pf_info}")
    print(f"RayScan 接入: {rs_info}")
    return 0


def cmd_skills(args) -> int:
    memory = Memory(args.data)
    skills = memory.list_skills(sort_by_rate=True)
    print(f"经验库技能 {len(skills)} 条（按成功率排序）:")
    for s in skills:
        print(f"  [{s.id}] {s.title}")
        print(f"      指纹: {s.target_fingerprint} | "
              f"成功率: {s.success_rate:.0%} "
              f"({s.successes}/{s.attempts}) | 证据: seq={s.evidence_refs}")
    return 0


def cmd_missions(args) -> int:
    memory = Memory(args.data)
    for m in memory.list_missions():
        print(f"  {m['id']} | {m['outcome']:<8} | {m['target']:<28} "
              f"| {m['objective'][:30]} | steps={len(m['steps'])}")
    return 0


def cmd_verify(args) -> int:
    evidence = EvidenceChain(Path(args.data) / "chain.jsonl")
    v = evidence.verify()
    print(f"证据链校验: {'OK' if v['ok'] else 'FAILED'} "
          f"（长度 {v['length']}）")
    if v["tampered"]:
        print(f"  被篡改: seq={v['tampered']}")
    if v["broken_links"]:
        print(f"  断链: seq={v['broken_links']}")
    return 0 if v["ok"] else 1


def cmd_mcp(args) -> int:
    """启动 MCP Server（stdio）：供 Claude/Codex/OpenCode 等客户端驱动。"""
    from penagent.mcp import PentestMCPServer

    server = PentestMCPServer(data_dir=args.data,
                              allowed_targets=args.targets or None)
    print(f"XPentest MCP Server 就绪（tools/list 可查工具，"
          f"targets={args.targets or '127.0.0.1/localhost'}）",
          file=sys.stderr)
    server.serve_stdio()
    return 0


def cmd_gaps(args) -> int:
    """技能盲区发现：工具使用统计 + 能力盲区建议。"""
    from penagent.gaps import analyze_gaps, analyze_gaps_llm

    memory = Memory(args.data)
    if args.llm:
        report = analyze_gaps_llm(memory)
    else:
        report = analyze_gaps(memory)
    print(f"作战记录 {report['missions']} 条: {report['outcome_counts']}")
    print(f"技能 {report['skills_count']} 条")
    print("\n工具使用统计:")
    for t, st in sorted(report["tool_usage"].items(),
                        key=lambda x: -x[1]["calls"]):
        print(f"  {t:<16} calls={st['calls']} ok={st['ok']} "
              f"blocked={st['blocked']} fail={st['fail']}")
    if report.get("blind_spots"):
        print("\nLLM 能力盲区:")
        for b in report["blind_spots"]:
            print(f"  - {b}")
    print("\n建议:")
    for s in report["suggestions"]:
        print(f"  - {s}")
    for r in report.get("recommendations", []):
        print(f"  - [LLM] {r}")
    if not report["suggestions"] and not report.get("recommendations"):
        print("  （暂无，继续积累作战数据）")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(
        prog="pentest", description="XPentest：LLM 驱动的个人渗透 Agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="执行渗透任务（LLM 决策）")
    p_run.add_argument("--target", required=True)
    p_run.add_argument("--objective", required=True)
    p_run.add_argument("--fp", default="", help="目标特征（指纹）")
    p_run.add_argument("--authorize", action="store_true",
                       help="授权危险工具")
    p_run.add_argument("--stealth", action="store_true",
                       help="对抗模式：技能按隐蔽优先排序（exposure 低者在前）")
    p_run.add_argument("--targets", default="", help="授权目标，逗号分隔")
    p_run.add_argument("--max-steps", type=int, default=12)
    p_run.add_argument("--data", default="data")
    p_run.add_argument("--rl-policy", default="data/rl/policy.json",
                       help="RL 策略 Q 表路径（不存在则跳过）")
    p_run.set_defaults(fn=cmd_run)

    p_ref = sub.add_parser("reflect", help="任务后反思（LLM 复盘→技能沉淀）")
    p_ref.add_argument("mission")
    p_ref.add_argument("--data", default="data")
    p_ref.set_defaults(fn=cmd_reflect)

    for name, fn, help_t in (
        ("agents", cmd_agents, "列出可用工具"),
        ("skills", cmd_skills, "经验库技能"),
        ("missions", cmd_missions, "作战记录"),
        ("verify", cmd_verify, "证据链校验"),
    ):
        p = sub.add_parser(name, help=help_t)
        p.add_argument("--data", default="data")
        p.set_defaults(fn=fn)

    p_ev = sub.add_parser("eval", help="进化评测（07 仿真对比）")
    p_ev.add_argument("--data", default="data")
    p_ev.set_defaults(fn=lambda a: __import__("subprocess").run(
        [sys.executable, "examples/eval_evolution.py"]).returncode)

    p_mcp = sub.add_parser("mcp", help="启动 MCP Server（stdio）")
    p_mcp.add_argument("--data", default="data")
    p_mcp.add_argument("--targets", default="",
                       help="授权目标，逗号分隔（默认 127.0.0.1/localhost）")
    p_mcp.set_defaults(fn=cmd_mcp)

    p_gaps = sub.add_parser("gaps", help="技能盲区发现（能力进化分析）")
    p_gaps.add_argument("--data", default="data")
    p_gaps.add_argument("--llm", action="store_true",
                        help="LLM 模式生成能力盲区清单")
    p_gaps.set_defaults(fn=cmd_gaps)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
