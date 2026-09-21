"""CLI 入口。

用法示例（本仓库未安装 console_script，入口是 `python -m penagent`；
仓库里没有 pyproject.toml / setup.py，所以不存在可直接调用的 `pentest` 命令）：
  python -m penagent run --target http://127.0.0.1:8080 --objective "侦察并总结目标"
  python -m penagent run --target ... --authorize   # 允许危险工具
  python -m penagent reflect <mission_id>           # 任务后反思（LLM 复盘）
  python -m penagent skills / missions / agents / verify
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from penagent.agent import PenAgent, Policy
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.memory import Memory


def _make_agent(args, registry=None, memory=None, evidence=None):
    mode = None
    mode_id = getattr(args, "mode", "") or ""
    if mode_id:
        from penagent.modes import load_mode

        mode = load_mode(mode_id)
    if registry is not None:
        reg = registry
    else:
        # 统一走注册中心：模式可用性、CTF 工具、适配层（PacketForge /
        # RayScan）都在这里装配。此前无模式分支自行拼装 ToolRegistry 并
        # 单独注册 adapters，与带模式分支的工具集不一致（R-9）。
        from penagent.registry import build_center

        reg = build_center(
            discover_mcp=bool(getattr(args, "discover_mcp", False))
        ).build_registry(mode)
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
                    max_steps=args.max_steps, skill_policy=skill_policy,
                    mode=mode)


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
    """列出工具（走统一注册中心，与内核实际挂载一致）。

    两层过滤都要生效才等于"实际可用"：
    1. 注册中心的 `entry.modes`（工具声明的模式可用性）
    2. `ModeProfile.capability` 的 allow/deny（模式对工具的裁决）
    所以这里直接构建与内核同款的注册表再列出，而不是只按声明过滤。
    此前本命令自行拼装 `ToolRegistry + builtins + adapters`，与 `--mode`
    实际挂载的注册表不一致（见 docs/修复待办清单.md R-9）。
    """
    from penagent.modes import load_mode
    from penagent.registry import build_center

    mode_id = getattr(args, "mode", "") or ""
    mode = load_mode(mode_id) if mode_id else None
    center = build_center(discover_mcp=getattr(args, "discover_mcp", False))
    registry = center.build_registry(mode)
    if mode is not None:
        # 第二层过滤：与 PenAgent.__init__ 完全同款——只按 entry.modes 过滤
        # 得到的是"工具声明在哪些模式可用"，还要过 ModeProfile.capability
        # 才是内核真正能执行的集合（漏这层会虚报可用工具）
        registry = mode.filtered_registry(registry)
    entries = {e.name: e for e in center.all_entries()}

    names = registry.names()
    scope = f"模式 {mode_id} 实际可执行" if mode_id else "无模式（内核工具全集）"
    print(f"工具 {len(names)} 个（{scope}）:")
    by_source: dict[str, int] = {}
    for name in names:
        spec = registry.get(name)
        entry = entries.get(name)
        source = entry.source if entry else "?"
        by_source[source] = by_source.get(source, 0) + 1
        danger = " [高危]" if spec.dangerous else ""
        print(f"  {name:<22} [{source}]{danger} "
              f"{spec.description[:34]}")
    print(f"\n按来源: {by_source}")
    for note in center.summary().get("notes", []):
        print(f"注: {str(note)[:110]}")
    return 0


def cmd_skills(args) -> int:
    memory = Memory(args.data)
    mode_id = getattr(args, "mode", "")
    if mode_id:
        # 记忆按模式分区（Memory(root) 与 Memory(root).for_namespace(模式)
        # 是两个目录）：agent 运行时读的是模式 namespace，种错了地方
        # 不报错、只是静默不生效
        from .modes import load_mode

        memory = memory.for_namespace(load_mode(mode_id).memory_namespace)
        print(f"目标分区: {memory.namespace}（模式 {mode_id}）")
    if getattr(args, "seed", False):
        from .skill_seeds import seed_skills

        refresh = bool(getattr(args, "refresh", False))
        report = seed_skills(memory, refresh=refresh)
        print(f"预置技能写入: 新增 {len(report['added'])} 条 {report['added']}；"
              f"刷新 {len(report['refreshed'])} 条 {report['refreshed']}；"
              f"已存在跳过 {len(report['skipped'])} 条 {report['skipped']}")
        print("（默认幂等：已存在的 id 不覆盖，避免抹掉复用统计；"
              "种子文件更新后用 --refresh 覆盖正文、保留统计）")
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


def cmd_dsh_sync(args) -> int:
    """把 DSH 宿主会话的工具调用事件并入内核证据链（审计通道）。"""
    from penagent.dsh_bridge import import_spool

    data = Path(args.data)
    report = import_spool(
        spool=args.spool or (data / "dsh-events.jsonl"),
        # 独立链（默认）：宿主会话的所有动作与内核任务链分开记，
        # 避免混进内核的 mission 窗口与 verify 口径；需要合并时用 --chain 指定
        chain_path=args.chain or (data / "dsh-chain.jsonl"),
        state_path=None if args.no_state else (data / "dsh-spool.state.json"),
        replay=args.replay,
        flush_open=args.flush_open,
    )
    if report.get("note"):
        print(f"无内容可导: {report['note']}")
        return 0
    print(f"DSH 事件导入: 新增记录 {report['records']} 条"
          f"（读入 {report['lines']} 行，未配对 {report['open_calls']} 条，"
          f"坏行 {report['bad_lines']}）")
    print(f"证据链: {report['chain']} · 校验 "
          f"{'OK' if report['chain_ok'] else 'FAILED'}"
          f"（长度 {report.get('chain_length')}）")
    if report.get("state_error"):
        print(f"  [warn] 增量状态未落盘（下次会重复导入）: {report['state_error']}")
    return 0 if report["chain_ok"] else 1


def cmd_mcp(args) -> int:
    """启动 MCP Server（stdio）：供 Claude/Codex/OpenCode 等客户端驱动。"""
    from penagent.mcp import PentestMCPServer
    from penagent.registry import build_center

    center = build_center(discover_mcp=getattr(args, "discover_mcp", False))
    server = PentestMCPServer(data_dir=args.data,
                              allowed_targets=args.targets or None,
                              authorize=getattr(args, "authorize", False),
                              default_mode=getattr(args, "default_mode", ""),
                              center=center)
    print(f"XPentest MCP Server 就绪（tools/list 可查工具，"
          f"targets={args.targets or '127.0.0.1/localhost'}，"
          f"authorize={'on' if getattr(args, 'authorize', False) else 'off'}，"
          f"default_mode={server.default_mode or '（未配置）'}，"
          f"工具数={len(server.registry.names())}）",
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
        prog="python -m penagent",
        description="XPentest：LLM 驱动的个人渗透 Agent")
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
    p_run.add_argument("--mode", default="",
                       help="模式档案 id（如 pentest-standard / ctf-web / "
                            "ctf-crypto）：决定工具白名单、权限档位、预算与判定器")
    p_run.add_argument("--max-steps", type=int, default=None,
                       help="步数上限（缺省取模式 budget.max_steps，无模式时 12）")
    p_run.add_argument("--data", default="data")
    p_run.add_argument("--rl-policy", default="data/rl/policy.json",
                       help="RL 策略 Q 表路径（不存在则跳过）")
    p_run.add_argument("--discover-mcp", action="store_true",
                       help="连接 mcp_servers.json 声明的外部 MCP Server"
                            "（seckb 知识库 / RayScan / Chameleon）；默认不连接，"
                            "避免启动被不可达的外部服务拖住")
    p_run.set_defaults(fn=cmd_run)

    p_ref = sub.add_parser("reflect", help="任务后反思（LLM 复盘→技能沉淀）")
    p_ref.add_argument("mission")
    p_ref.add_argument("--data", default="data")
    p_ref.set_defaults(fn=cmd_reflect)

    p_ag = sub.add_parser("agents", help="列出可用工具")
    p_ag.add_argument("--data", default="data")
    p_ag.add_argument("--mode", default="",
                      help="只看该模式可见的工具（缺省列出全部已登记）")
    p_ag.add_argument("--discover-mcp", action="store_true",
                      help="列出前先连接外部 MCP Server"
                           "（seckb 知识库 / RayScan / Chameleon）")
    p_ag.set_defaults(fn=cmd_agents)

    for name, fn, help_t in (
        ("skills", cmd_skills, "经验库技能"),
        ("missions", cmd_missions, "作战记录"),
        ("verify", cmd_verify, "证据链校验"),
        ("dsh-sync", cmd_dsh_sync, "导入 DSH 会话事件到证据链（审计桥）"),
    ):
        p = sub.add_parser(name, help=help_t)
        p.add_argument("--data", default="data")
        if name == "dsh-sync":
            p.add_argument("--spool", default="",
                           help="宿主桥落的事件文件（缺省 <data>/dsh-events.jsonl）")
            p.add_argument("--replay", action="store_true",
                           help="忽略增量偏移，从头重放（换链重建用）")
            p.add_argument("--no-state", action="store_true",
                           help="不记录增量状态（每次全量导入）")
            p.add_argument("--chain", default="",
                           help="目标证据链（缺省 <data>/dsh-chain.jsonl，"
                                "独立于内核任务链）")
            p.add_argument("--flush-open", action="store_true",
                           help="把仍未配对的调用按 ok=None 落链（会话已结束时用）")
        if name == "skills":
            p.add_argument("--seed", action="store_true",
                           help="写入预置技能种子（幂等；来源见 "
                                "penagent/skill_seeds.py）")
            p.add_argument("--refresh", action="store_true",
                           help="配合 --seed：用种子文件的新定义覆盖已有技能"
                                "正文（保留成功率等学习统计）")
            p.add_argument("--mode", default="",
                           help="写到指定模式的记忆分区（如 pentest-standard）"
                                "——agent 运行读的是模式分区，不指定则写默认分区")
        p.set_defaults(fn=fn)

    p_ev = sub.add_parser("eval", help="进化评测（07 仿真对比）")
    p_ev.add_argument("--data", default="data")
    p_ev.set_defaults(fn=lambda a: __import__("subprocess").run(
        [sys.executable, "examples/eval_evolution.py"]).returncode)

    p_mcp = sub.add_parser("mcp", help="启动 MCP Server（stdio）")
    p_mcp.add_argument("--data", default="data")
    p_mcp.add_argument("--targets", default="",
                       help="授权目标，逗号分隔（默认 127.0.0.1/localhost）")
    p_mcp.add_argument("--authorize", action="store_true",
                       help="操作员级高危授权：开启后白名单内的高危工具才放行"
                            "（工具调用参数里的 authorize 一律不生效）")
    p_mcp.add_argument("--default-mode", default="",
                       help="服务端默认模式 id：pentest_run 未显式指定 mode 时"
                            "回落到它（如 pentest-standard）。不配则该路径不加"
                            "模式约束——沙箱裁决缺失，危险工具直跑宿主")
    p_mcp.add_argument("--discover-mcp", action="store_true",
                       help="连接 mcp_servers.json 声明的外部 MCP Server"
                            "（seckb 知识库 / RayScan / Chameleon）；默认不连接，"
                            "避免启动被不可达的外部服务拖住")
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
