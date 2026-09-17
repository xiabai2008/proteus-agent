"""反思引擎：任务后 LLM 复盘 -> 经验/技能沉淀（自我进化核心）。

LLM 分析作战记录与证据链，产出：
- 成败归因（为什么成功/失败）
- 可复用技能（成功任务：步骤/工具/适用指纹/证据引用）
技能入库前校验：evidence_refs 必须真实存在（反幻觉），否则拒绝入库。
"""
from __future__ import annotations

from typing import Optional

from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig, LLMError, chat_json
from penagent.memory import Memory, Skill

REFLECT_PROMPT = """你是 XPentest 的反思引擎。分析以下作战记录，输出严格 JSON：

{"outcome_analysis": "成败归因（为什么成功/失败，哪些工具/参数/策略起了作用）",
 "skill": null 或 {
   "title": "技能名",
   "target_fingerprint": "适用目标特征（如: python web 应用）",
   "steps": ["可复用步骤1", "步骤2"],
   "tools": ["用到的工具名"],
   "evidence_refs": [关键证据seq]
 }}

要求：
- 仅当任务成功且步骤可复用时输出 skill，否则 null；
- evidence_refs 只能引用作战记录中真实存在的 seq；
- 若任务失败，分析失败模式与改进建议（写入 outcome_analysis）。

作战记录：
{mission}"""


class Reflector:
    """反思引擎。"""

    def __init__(self, llm: Optional[LLMConfig] = None) -> None:
        self.llm = llm or LLMConfig.from_env()

    # ------------------------------------------------------------------
    def reflect(self, mission_id: str, memory: Memory,
                evidence: EvidenceChain) -> tuple[str, Optional[Skill]]:
        mission = memory.get_mission(mission_id)
        system = REFLECT_PROMPT.replace(
            "{mission}", json_dumps(mission))
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": "请反思并输出 JSON"},
        ]
        try:
            data = chat_json(self.llm, messages, temperature=0.2)
        except LLMError:
            return "反思失败（LLM 不可用）", None

        analysis = str(data.get("outcome_analysis", ""))
        memory.finish(mission_id, mission.get("outcome", "unknown"), analysis)

        skill_data = data.get("skill")
        if not skill_data:
            return analysis, None

        refs = [int(r) for r in skill_data.get("evidence_refs", [])]
        valid = evidence.valid_refs(refs)
        if len(valid) != len(refs):
            return (analysis + "（技能因证据引用无效被拒绝入库）", None)

        import uuid

        skill = Skill(
            id=str(uuid.uuid4())[:8],
            title=skill_data.get("title", "未命名技能"),
            target_fingerprint=skill_data.get("target_fingerprint", ""),
            steps=skill_data.get("steps", []),
            tools=skill_data.get("tools", []),
            evidence_refs=valid,
            source_mission=mission_id,
        )
        memory.add_skill(skill)
        return analysis, skill


def json_dumps(obj) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, indent=2)
