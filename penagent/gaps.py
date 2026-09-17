"""技能盲区发现（进化第五单元）：工具使用统计 + 失败模式分析。

- 纯统计模式：工具调用热力 / 失败率 / 被拦截情况 → 规则化建议
- LLM 模式（可选）：统计结果喂 LLM，生成"待补能力清单"
"""
from __future__ import annotations

from typing import Optional

from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig, chat_json
from penagent.memory import Memory


def analyze_gaps(memory: Memory,
                 evidence: Optional[EvidenceChain] = None) -> dict:
    """基于作战记录统计工具使用与失败模式。"""
    missions = memory.list_missions()
    tool_stats: dict = {}
    outcome_counts = {"success": 0, "failed": 0, "running": 0}

    for m in missions:
        outcome_counts[m.get("outcome", "running")] = \
            outcome_counts.get(m.get("outcome", "running"), 0) + 1
        for step in m.get("steps", []):
            t = step.get("tool", "?")
            st = tool_stats.setdefault(
                t, {"calls": 0, "ok": 0, "blocked": 0, "fail": 0})
            st["calls"] += 1
            if step.get("blocked"):
                st["blocked"] += 1
            elif step.get("ok"):
                st["ok"] += 1
            else:
                st["fail"] += 1

    suggestions = []
    for t, st in tool_stats.items():
        fail_rate = st["fail"] / st["calls"] if st["calls"] else 0
        if st["calls"] >= 2 and fail_rate > 0.5:
            suggestions.append(
                f"工具 {t} 失败率 {fail_rate:.0%}（{st['fail']}/{st['calls']}），"
                "建议检查参数或更新工具版本")
        if st["blocked"]:
            suggestions.append(
                f"高危工具 {t} 被护栏拦截 {st['blocked']} 次——"
                "若是必要能力，请在授权目标上显式授权使用")

    unused = [
        s.title for s in memory.list_skills()
        if not any(s.title in m.get("reflection", "")
                   or s.source_mission == m.get("id")
                   for m in missions)
    ]
    return {
        "missions": len(missions),
        "outcome_counts": outcome_counts,
        "tool_usage": tool_stats,
        "suggestions": suggestions,
        "unused_skills": unused,
        "skills_count": len(memory.list_skills()),
    }


GAPS_PROMPT = """你是 XPentest 的能力规划师。基于以下工具使用统计，输出待补能力清单 JSON：

{"blind_spots": ["能力盲区1（如: 缺少 XX 类型漏洞的检测工具）", ...],
 "recommendations": ["补强建议（新工具/参数优化/技能沉淀方向）", ...]}

统计：
{stats}

要求：盲区与建议必须基于统计中的实际数据（失败率/未使用工具/任务失败模式），
不要泛泛而谈。"""


def analyze_gaps_llm(memory: Memory, llm: Optional[LLMConfig] = None) -> dict:
    """LLM 模式：基于统计生成能力盲区分析。"""
    stats = analyze_gaps(memory)
    if not stats["missions"]:
        return {**stats, "blind_spots": [], "recommendations": [
            "尚无作战数据，先执行任务积累经验"]}
    config = llm or LLMConfig.from_env()
    import json as _json

    try:
        data = chat_json(config, [
            {"role": "system", "content": GAPS_PROMPT.replace(
                "{stats}", _json.dumps(stats, ensure_ascii=False,
                                       indent=2))},
            {"role": "user", "content": "请输出能力清单 JSON"},
        ], temperature=0.2)
    except Exception as exc:
        return {**stats, "blind_spots": [], "recommendations": [],
                "note": f"LLM 分析失败: {exc}"}
    stats["blind_spots"] = data.get("blind_spots", [])
    stats["recommendations"] = data.get("recommendations", [])
    return stats
