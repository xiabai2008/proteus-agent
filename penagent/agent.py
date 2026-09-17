"""LLM 决策内核（ReAct 循环）。

流程：LLM 规划（目标+工具 schema+相关技能）→ 安全护栏校验 → 工具执行
→ 观察 → 证据固化 → 再次决策 → 直到 done。
结论必须引用真实证据 seq（反幻觉校验），否则拒绝产出。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional

from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig, LLMError, chat_json
from penagent.memory import Memory
from penagent.tools import ToolRegistry

SYSTEM_PROMPT = """你是 XPentest——一个 LLM 驱动的渗透测试 Agent。
约束：
1. 只对授权目标执行动作；涉及危险工具必须谨慎并明确说明。
2. 输出严格 JSON（不要 markdown 代码块），两种格式二选一：
   A. {"thought": "推理", "tool": "工具名", "args": {...}}
   B. {"thought": "总结", "done": true, "summary": "结论", "evidence_refs": [证据seq]}
3. evidence_refs 只能引用你实际看到过的证据 seq（不可编造）。
4. 每次只调用一个工具，观察结果后再决定下一步。
5. 无法推进时输出 done 并如实说明。

可用工具：
{tools}

相关历史技能（可复用，仅参考）：
{skills}"""


@dataclass
class MissionResult:
    mission_id: str = ""
    target: str = ""
    objective: str = ""
    outcome: str = "running"          # success | failed | blocked
    steps: int = 0
    summary: str = ""
    evidence_refs: list[int] = field(default_factory=list)
    injected_skills: list[str] = field(default_factory=list)
    reflection: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class Policy:
    """安全护栏：授权目标 + 高危动作确认。规则写死，不参与决策。"""

    def __init__(self, allowed_targets: Optional[list[str]] = None,
                 authorize: bool = False) -> None:
        self.allowed_targets = list(allowed_targets or
                                    ["127.0.0.1", "localhost"])
        self.authorize = authorize

    def check(self, tool: str, spec, args: dict) -> tuple[bool, str]:
        # 高危动作
        if getattr(spec, "dangerous", False) and not self.authorize:
            return False, (f"高危工具 {tool} 未授权（--authorize 才可执行）")
        # 授权目标校验
        for key in ("host", "url", "domain", "target", "base_url"):
            value = args.get(key)
            if not value:
                continue
            if not self._in_scope(value):
                return False, (f"目标 {value!r} 不在授权范围 "
                               f"{self.allowed_targets}")
        return True, ""

    def _in_scope(self, value: str) -> bool:
        import urllib.parse

        if value.startswith(("http://", "https://")):
            host = urllib.parse.urlparse(value).hostname or ""
        elif ":" in value and not value.startswith("["):
            host = value.split(":", 1)[0]
        else:
            host = value.split("/")[0]
        return any(host == t or host.endswith("." + t.lstrip("."))
                   for t in self.allowed_targets)


class PenAgent:
    """LLM 决策 + 工具调度 + 证据固化的渗透 Agent。"""

    def __init__(self, registry: ToolRegistry, memory: Memory,
                 evidence: EvidenceChain, llm: Optional[LLMConfig] = None,
                 policy: Optional[Policy] = None,
                 max_steps: int = 12,
                 skill_policy: Optional["SkillPolicy"] = None) -> None:
        self.registry = registry
        self.memory = memory
        self.evidence = evidence
        self.llm = llm or LLMConfig.from_env()
        self.policy = policy or Policy()
        self.max_steps = max_steps
        self.skill_policy = skill_policy   # RL 技能选择策略（可选）
        self._used_skills: list = []

    def _record_skill_outcomes(self, success: bool) -> None:
        """任务结束后把结果回写到本次复用的技能（M3 成功率进化）。"""
        for skill in self._used_skills:
            current = self.memory.find_skills(skill.target_fingerprint)
            target = next((s for s in current if s.id == skill.id), None)
            if target is not None:
                target.record_outcome(success)
                self.memory.update_skill(target)
        self._used_skills = []

    def _rank_skills(self, skills: list, fingerprint: str,
                     stealth: bool = False) -> list:
        """技能注入排序：策略最优技能优先，其余按成功率降序。

        stealth=True：非策略部分按隐蔽优先（exposure 升序，成功率次级）
        排序——检测感知的进化排序接入注入管线。
        策略接口统一：best_skill(fingerprint) -> 技能 id
        （支持 Q-learning SkillPolicy 与 PPO PPOSkillPolicy）。
        """
        if stealth:
            ranked = sorted(
                skills,
                key=lambda s: (s.exposure if s.exposure is not None
                               else 10 ** 9, -s.success_rate))
        else:
            ranked = sorted(skills, key=lambda s: -s.success_rate)
        if self.skill_policy is None or not ranked:
            return ranked[-3:]
        best = self.skill_policy.best_skill(fingerprint)
        if best:
            idx = next(
                (i for i, s in enumerate(ranked)
                 if s.title == best or best.lower() in s.title.lower()),
                None)
            if idx is not None:
                ranked.insert(0, ranked.pop(idx))
        return ranked[-3:]

    # ------------------------------------------------------------------
    def run(self, target: str, objective: str,
            fingerprint: str = "", stealth: bool = False) -> MissionResult:
        mission_id = self.memory.new_mission(target, objective)
        mission = MissionResult(mission_id=mission_id, target=target,
                                objective=objective)
        skills = self.memory.find_skills(fingerprint or target)
        skills = self._rank_skills(skills, fingerprint or target,
                                   stealth=stealth)
        mission.injected_skills = [s.title for s in skills[-3:]]
        self._used_skills = skills[-3:]   # 本次任务复用的技能（结果回写）
        system = SYSTEM_PROMPT.replace(
            "{tools}", json.dumps(self.registry.schemas(),
                                  ensure_ascii=False)).replace(
            "{skills}", json.dumps([s.to_dict() for s in skills[-3:]],
                                   ensure_ascii=False))
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": (
                f"目标: {target}\n目标特征: {fingerprint or '未知'}\n"
                f"任务: {objective}\n"
                f"当前时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")},
        ]

        for step in range(1, self.max_steps + 1):
            mission.steps = step
            try:
                decision = chat_json(self.llm, messages)
            except LLMError as exc:
                mission.outcome = "failed"
                mission.summary = f"LLM 调用失败: {exc}"
                self.memory.finish(mission_id, mission.outcome,
                                   mission.summary)
                self._record_skill_outcomes(False)
                return mission

            self.evidence.append("decision", {
                "step": step, "thought": decision.get("thought", "")})

            if decision.get("done"):
                refs = [int(r) for r in decision.get("evidence_refs", [])]
                valid = self.evidence.valid_refs(refs)
                if refs and len(valid) != len(refs):
                    # 反幻觉：结论引用不存在的证据 -> 拒绝产出
                    mission.outcome = "failed"
                    mission.summary = (
                        f"反幻觉拦截：结论引用 {len(refs) - len(valid)} 条"
                        f"不存在的证据")
                    self.memory.finish(mission_id, mission.outcome,
                                       mission.summary)
                    self._record_skill_outcomes(False)
                    return mission
                mission.outcome = "success"
                mission.summary = decision.get("summary", "")
                mission.evidence_refs = valid
                self.evidence.append("conclusion", {
                    "summary": mission.summary, "evidence_refs": valid})
                self.memory.finish(mission_id, mission.outcome)
                self._record_skill_outcomes(True)
                return mission

            tool = decision.get("tool", "")
            args = decision.get("args", {}) or {}
            spec = self.registry.get(tool)
            if spec is None:
                messages.append({"role": "user",
                                 "content": f"工具 {tool!r} 不存在，请重新选择"})
                continue
            allowed, reason = self.policy.check(tool, spec, args)
            if not allowed:
                self.evidence.append("tool_call", {"tool": tool,
                                                   "args": args,
                                                   "blocked": True,
                                                   "reason": reason})
                messages.append({"role": "user",
                                 "content": f"护栏拦截: {reason}"})
                self.memory.add_step(mission_id, {
                    "step": step, "tool": tool, "args": args,
                    "blocked": True, "reason": reason})
                continue

            tool_result = self.registry.execute(tool, args)
            self.evidence.append("tool_call", {
                "tool": tool, "args": args, "ok": tool_result.ok,
                "output": str(tool_result.output)[:1500],
                "error": tool_result.error,
            })
            self.memory.add_step(mission_id, {
                "step": step, "tool": tool, "args": args,
                "ok": tool_result.ok, "output": str(tool_result.output)[:800],
            })
            messages.append({
                "role": "user",
                "content": (f"工具 {tool} 执行结果:\n"
                            f"{json.dumps(tool_result.to_dict(), ensure_ascii=False)[:2500]}")})

        mission.outcome = "failed"
        mission.summary = f"超过最大步数 {self.max_steps}，任务未完成"
        self.memory.finish(mission_id, mission.outcome, mission.summary)
        self._record_skill_outcomes(False)
        return mission
