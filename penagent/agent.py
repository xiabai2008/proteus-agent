"""LLM 决策内核（ReAct 循环）。

流程：LLM 规划（目标+工具 schema+相关技能）→ 安全护栏校验 → 工具执行
→ 观察 → 证据固化 → 再次决策 → 直到 done。
结论必须引用真实证据 seq（反幻觉校验），否则拒绝产出。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig, LLMError, LLMOutputError, chat_json
from penagent.memory import Memory
from penagent.modes import ModeProfile
from penagent.scope import is_read_only_call
from penagent.tools import FROZEN_ARGS_KEY, ToolRegistry
from penagent.verifier import (EvidenceChainVerifier, Verifier,
                               build_verifier, oracle_evidence)

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

# 内核侧重复失败检测（R-39）的缺省阈值：同工具 + 同参数**连续**失败到该次数，
# 下一次同调用不再执行，改为回灌纠正指令（含上次失败理由 + 换思路）。
# 与宿主侧监督层（`dsh/.agent-presets/_shared/proteus-supervisor.mjs` 的
# sameToolLimit）同源，但内核更早介入：宿主侧数的是**会话内重复**（无论成败），
# 内核数的是**连续失败**——每次失败都有模型可见的输出，"连续 3 次同参失败"
# 基本可断定模型没读失败信息（实测：一次 CTF 会话里 `file_type` 用了错路径，
# 同参失败 57 次）。
# 刻意不进 ModeProfile：这是对模型行为的纠偏，不是模式语义，各模式的判据相同；
# 新增配置面要有真实消费场景（见 docs/修复待办清单.md R-39）。
REPEAT_FAILURE_LIMIT = 3

# LLM 输出不可解析（`LLMOutputError`）时的重试上限（R-40）：真机渗透任务
# 第 13 步收到 `<｜｜DSML｜｜ invoke name="http_raw">` 形态的 XML 工具调用，
# `chat_json` 抛"输出不是合法 JSON" → 13 步成果（8 分钟）当场作废。
# 与调用失败（网络/HTTP/超时）不同，输出形态失误回灌一条"只输出 JSON"提示
# 通常就能救回来，所以这里**重试而非收口**：每次失败都留证据（含原始输出
# 片段）便于诊断，前 3 次不可解析都回灌纠正提示重试（共 4 次尝试），
# 第 4 次仍拿不到 JSON 才判任务失败。
# 与 REPEAT_FAILURE_LIMIT 同理，刻意不进 ModeProfile（模型行为纠偏，
# 不是模式语义，各模式判据相同）。
LLM_PARSE_RETRY_LIMIT = 3


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
    #: CTF 判定器接受性：True=判定器（native_emu）接受过该 flag；
    #: False=正则命中但无接受留证（"未验证"，不判失败）；None=不适用。
    flag_verified: Optional[bool] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class Policy:
    """安全护栏：模式能力/权限裁决 + 授权目标 + 高危动作确认。

    规则写死，不参与决策。模式驱动部分（硬规则 1/3，全部在工具执行前生效）：
    - capability.deny / permission.hard_deny：直接拒绝，任何运行期开关都不可放行；
    - permission.require_confirm 与 default=ask：记为 blocked 待人工确认，
      运行期 `authorize=True`（操作者已授权）方可放行；
    - capability.constraints：执行前把冻结参数追加进 args；
    - scope.target_allowlist：只可收紧，不可放宽运行期显式授权范围。

    不传 mode 时行为与升级前完全一致（向后兼容）。
    """

    def __init__(self, allowed_targets: Optional[list[str]] = None,
                 authorize: bool = False,
                 mode: Optional[ModeProfile] = None,
                 reference_targets: Optional[list[str]] = None) -> None:
        self._runtime_targets = self.normalize_targets(allowed_targets)
        self.allowed_targets = self._narrow_by_mode(self._runtime_targets, mode)
        self.authorize = authorize
        self.mode = mode
        #: 只读参考站（公开 WP / 知识库）：**只对只读工具放行**（GET/HEAD 类
        #: 读取），攻击面工具永远只看 allowed_targets。见 scope.is_read_only_call。
        self.reference_targets = [str(t).strip() for t in
                                  (reference_targets or []) if str(t).strip()]

    @staticmethod
    def normalize_targets(value) -> list[str]:
        """把授权目标规范成列表，支持 "a,b" 字符串与可迭代对象。

        **必须做这一步**：字符串本身是 iterable，`list("127.0.0.1")` 会炸成
        单字符列表 `['1','2','7','.',...]`；而白名单匹配用的是
        `host.endswith("." + t)`，单字符条目会意外命中大量主机（条目 `'2'`
        命中 `127.0.0.2`、条目 `'1'` 命中 `192.168.1.1`）——白名单等于失效。
        CLI 的 `--targets` 是逗号分隔字符串，正是这条路径踩中过。
        空值回落到默认回环白名单。
        """
        if value is None or value == "":
            return ["127.0.0.1", "localhost"]
        if isinstance(value, str):
            items = value.split(",")
        else:
            items = list(value)
        targets = [str(item).strip() for item in items]
        targets = [t for t in targets if t]
        return targets or ["127.0.0.1", "localhost"]

    @staticmethod
    def _narrow_by_mode(runtime_targets: list[str],
                        mode: Optional[ModeProfile]) -> list[str]:
        """模式白名单只可收紧：与运行期显式授权取交集（硬规则 3）。

        模式声明 "required"（空列表）时不改变运行期授权范围；
        模式声明的目标若从未被运行期授权过，一律不生效（取交集后为空即全拒）。
        """
        if mode is None or not mode.scope.target_allowlist:
            return list(runtime_targets)
        authorized = {t.strip().lower() for t in runtime_targets if t.strip()}
        return [t for t in mode.scope.target_allowlist
                if t.strip().lower() in authorized]

    def bind_mode(self, mode: ModeProfile) -> "Policy":
        """返回挂载了模式裁决的副本（不改动原实例）。"""
        return Policy(allowed_targets=self._runtime_targets,
                      authorize=self.authorize, mode=mode)

    def level_for(self, tool: str, spec=None) -> str:
        """工具适用的权限档位：ok | ask | deny。

        无模式时沿用升级前语义：危险工具未授权 = ask，其余 = ok。
        """
        if self.mode is not None:
            return self.mode.permission.level_for(tool)
        if spec is not None and getattr(spec, "dangerous", False):
            return "ok" if self.authorize else "ask"
        return "ok"

    def apply_constraints(self, tool: str, args: dict) -> dict:
        """把模式冻结参数追加进 args（执行前调用，机制性生效）。

        冻结串按命令行 token 追加，由 ToolRegistry 在执行时拼到命令尾部；
        函数型工具不受影响（其入参按 spec.parameters 过滤）。
        """
        frozen = (self.mode.capability.constraint_for(tool)
                  if self.mode is not None else "")
        if not frozen:
            return args
        merged = dict(args or {})
        existing = str(merged.get(FROZEN_ARGS_KEY, "")).strip()
        merged[FROZEN_ARGS_KEY] = (f"{existing} {frozen}".strip()
                                   if existing else frozen)
        return merged

    def check(self, tool: str, spec, args: dict) -> tuple[bool, str]:
        # 模式能力与权限档位裁决（先于任何执行动作）
        if self.mode is not None:
            if not self.mode.capability.allows(tool):
                return False, (f"模式 {self.mode.id} 禁用该工具："
                               f"{self.mode.capability.denial_reason(tool)}")
            level = self.mode.permission.level_for(tool)
            if level == "deny":
                return False, (f"模式 {self.mode.id} 权限档位 deny："
                               f"{tool} 被硬拒绝执行")
            if level == "ask" and not self.authorize:
                return False, (f"模式 {self.mode.id} 权限档位 ask："
                               f"{tool} 待人工确认（未执行）")
            # 出网开关（scope.network_egress）：关闭时拒绝声明需要出网的
            # 工具——机制性裁决，容器网络的 --network none 是第二道冗余
            if not self.mode.scope.network_egress \
                    and getattr(spec, "network", False):
                return False, (f"模式 {self.mode.id} 关闭网络出口"
                               f"（scope.network_egress=false）："
                               f"{tool} 声明需要出网，拒绝执行")
        # 高危动作
        if getattr(spec, "dangerous", False) and not self.authorize:
            return False, (f"高危工具 {tool} 未授权（--authorize 才可执行）")
        # 授权目标校验
        for key in ("host", "url", "domain", "target", "base_url"):
            value = args.get(key)
            if not value:
                continue
            if self._in_scope(value):
                continue
            # 只读参考站（2026-09-27 实测新增）：公开 WP / 知识库的**读取**
            # （只读工具 + GET/HEAD）单独放行——"给人看一篇 WP"不该要求把
            # 公开站点写进目标授权；写动作与攻击面工具不受这条影响。
            if self.reference_targets and is_read_only_call(tool, args) \
                    and self._matches(value, self.reference_targets):
                continue
            return False, (f"目标 {value!r} 不在授权范围 "
                           f"{self.allowed_targets}。"
                           f"若确需访问：**读公开资料**（WP / 知识库）由人执行 "
                           f"/proteus-scope add-ref {value}（CLI："
                           f"python -m penagent scope --add-ref {value}）"
                           f"——只对读取类工具生效；**对目标的动作**由人执行 "
                           f"/proteus-scope add {value}（CLI："
                           f"python -m penagent scope --add {value}）"
                           f"显式授权后重试——模型不能自我授权")
        return True, ""

    @staticmethod
    def _host_of(value: str) -> str:
        import urllib.parse

        text = str(value or "")
        if text.startswith(("http://", "https://")):
            return urllib.parse.urlparse(text).hostname or ""
        if ":" in text and not text.startswith("["):
            return text.split(":", 1)[0]
        return text.split("/")[0]

    @classmethod
    def _matches(cls, value: str, targets) -> bool:
        host = cls._host_of(value)
        return any(host == t or host.endswith("." + t.lstrip("."))
                   for t in targets)

    def _in_scope(self, value: str) -> bool:
        return self._matches(value, self.allowed_targets)

    def _in_reference(self, value: str) -> bool:
        return self._matches(value, self.reference_targets)


class PenAgent:
    """LLM 决策 + 工具调度 + 证据固化的渗透 Agent。"""

    def __init__(self, registry: ToolRegistry, memory: Memory,
                 evidence: EvidenceChain, llm: Optional[LLMConfig] = None,
                 policy: Optional[Policy] = None,
                 skill_policy: Optional["SkillPolicy"] = None,
                 mode: Optional[ModeProfile] = None,
                 verifier: Optional[Verifier] = None,
                 max_steps: Optional[int] = None,
                 on_event: Optional[Callable[[dict], None]] = None) -> None:
        self.mode = mode
        # 成功判定器：模式决定判据（CTF 挂 flag 正则，渗透挂证据链）；
        # 不传模式时沿用升级前的证据链语义（require_poc 关闭）
        if verifier is not None:
            self.verifier = verifier
        elif mode is not None:
            self.verifier = build_verifier(mode.verifier)
        else:
            self.verifier = EvidenceChainVerifier()
        # 模式约束在工具执行前机制性生效：被 capability 禁用的工具不进入
        # 注册表——既不进 system prompt 的工具 schema，也无法被执行。
        self.registry = (mode.filtered_registry(registry)
                         if mode is not None else registry)
        if mode is not None and getattr(self.registry, "sandbox", None) is None:
            # 注册表必须带沙箱策略：否则换一个构造路径就绕过了隔离档位
            from penagent.sandbox import build_sandbox

            self.registry.sandbox = build_sandbox(
                mode.sandbox, egress=mode.scope.network_egress)
        # 记忆按模式分区：读写只落 current namespace，模式间互不串库
        self.memory = (memory.for_namespace(mode.memory_namespace)
                       if mode is not None else memory)
        self.evidence = evidence
        self.llm = llm or LLMConfig.from_env()
        self.policy = policy or Policy()
        if mode is not None and self.policy.mode is None:
            # 显式传入的 Policy 也必须挂上模式裁决，避免绕过模式约束
            self.policy = self.policy.bind_mode(mode)
        # 闸门挂在注册表上（而非只在 run() 里调用）：目标白名单、高危授权与
        # 协议白名单因此对所有入口生效——ReAct 循环、MCP 底层工具、Web 子进程
        # 都走 registry.execute，绕不过去（硬规则 1/3）
        if getattr(self.registry, "gate", None) is None:
            from penagent.policy_gate import PolicyGate

            self.registry.gate = PolicyGate(self.policy)
        # 步数预算：显式传参优先；否则由模式 budget 决定（不传模式时沿用 12）
        if max_steps is None:
            max_steps = mode.budget.max_steps if mode is not None else 12
        self.max_steps = max_steps
        # 进度事件回调（T1/F1）：None = 不外发；异常被吞（fail-open）
        self.on_event = on_event
        # 时长预算（budget.max_minutes）：超限走"换策略收口"而非硬退出；
        # 不传模式时无时长上限（升级前行为）
        self.max_minutes = (mode.budget.max_minutes
                            if mode is not None else None)
        self.skill_policy = skill_policy   # RL 技能选择策略（可选）
        self._used_skills: list = []
        # 重复失败检测（R-39）计数：指纹 -> 连续失败次数 / 上次失败原因 /
        # 已拦截次数。按任务重置（见 run 开头），跨任务不继承。
        self._repeat_failures: dict[str, int] = {}
        self._repeat_errors: dict[str, str] = {}
        self._repeat_blocks: dict[str, int] = {}

    def _record_skill_outcomes(self, success: bool) -> None:
        """任务结束后把结果回写到本次复用的技能（M3 成功率进化）。"""
        for skill in self._used_skills:
            current = self.memory.find_skills(skill.target_fingerprint)
            target = next((s for s in current if s.id == skill.id), None)
            if target is not None:
                target.record_outcome(success)
                self.memory.update_skill(target)
        self._used_skills = []

    def _filter_mode_skills(self, skills: list) -> list:
        """按模式的技能包过滤（`mode.skills` 的机制性消费）。

        AGENTS.md 第 4 节把 `skills` 定义为"本模式技能包 / 技能检索过滤"，
        但该字段此前无任何消费方（仅 Web 控制台展示与测试断言）。这里让它
        真正生效：按 `Skill.category` 与本模式声明的技能包求交。

        语义上只过滤"**明确标注了 category 且不在白名单内**"的技能——未标注
        （category 为空）的保留，避免因历史数据未标注而被静默丢弃；
        无模式或未声明技能包时完全不过滤（保持升级前行为）。
        """
        if self.mode is None or not self.mode.skills:
            return skills
        allowed = set(self.mode.skills)
        return [s for s in skills
                if not s.category or s.category in allowed]

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

    def _append_evidence(self, kind: str, mission_id: str, step: int,
                         content: dict):
        """带任务归属的留证（P2-3）。

        为什么必须带：链是**扁平**的，而 `mission`/`step` 是层级视图
        （Task → Action → Artifact）唯一的关联依据。此前链记录里没有任务号，
        于是"这条 evidence 属于哪次任务"只能靠 seq 区间猜——`_mission_context`
        就是这么做的（按 `since_seq` 划范围），一旦并发或分叉就不可靠。
        """
        payload = {"mission": mission_id, "step": step, **content}
        return self.evidence.append(kind, payload)

    def _blocked(self, mission_id: str, step: int, tool: str, args: dict,
                 reason: str, level: str) -> dict:
        """记录被模式/护栏/重复失败检测拦截的工具调用（证据链 + 作战记录），
        回灌消息。

        `level` 取护栏档位（ok/ask/deny）或 "loop"（重复失败检测，见 `_loop_reason`）；
        证据链与作战记录都带上它，审计视图才能区分"被哪种判据拦的"。
        """
        record = self._append_evidence("tool_call", mission_id, step, {
            "tool": tool, "args": args,
            "blocked": True, "reason": reason, "level": level})
        self.memory.add_step(mission_id, {"step": step, "tool": tool,
                                          "args": args, "blocked": True,
                                          "reason": reason, "level": level,
                                          "evidence_seq": record.seq})
        return {"role": "user", "content": f"护栏拦截: {reason}"}

    # ------------------------------------------------------------------
    # 内核侧重复失败检测（R-39）
    # ------------------------------------------------------------------
    @staticmethod
    def _fingerprint(tool: str, args: dict) -> str:
        """调用指纹：工具名 + 规范化参数（键序无关，嵌套同样排序）。

        与宿主侧监督层同构（`proteus-supervisor.mjs` 的 `fingerprint`）：
        两边口径一致，"内核数的是哪一次调用"与"宿主数的是哪一次"是同一件事。
        """
        try:
            body = json.dumps(args or {}, sort_keys=True,
                              ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            body = str(args)
        return f"{tool}::{body}"

    def _loop_reason(self, tool: str, args: dict) -> str:
        """同工具 + 同参数连续失败到阈值 -> 纠正指令文案；未达阈值返回空串。

        命中即**拒绝执行**（与宿主侧监督层的 deny 同语义）：再发一次只会拿到
        同一个失败，白烧一步预算；模型缺的信号是"上次为什么失败 + 换思路"。
        纯判断、无副作用（拦截计数就地累加，便于文案说明是第几次），计数与
        留痕由调用方做。
        """
        key = self._fingerprint(tool, args)
        fails = self._repeat_failures.get(key, 0)
        if fails < REPEAT_FAILURE_LIMIT:
            return ""
        blocks = self._repeat_blocks.get(key, 0) + 1
        self._repeat_blocks[key] = blocks
        last = self._repeat_errors.get(key, "")
        return (f"同一调用（{tool} 同参数）已连续失败 {fails} 次，"
                f"本次为第 {blocks} 次拦截——重复调用不会带来新信息。"
                f"上次失败原因：{last or '（工具未给出原因）'}。"
                "换思路：改写参数（例如只取需要的片段、缩小范围）、"
                "换一个工具验证同一个假设，或停下把卡点如实告诉人；"
                "确实无路可走时直接输出 done 并说明未完成。")

    def _record_tool_outcome(self, tool: str, args: dict, result) -> None:
        """按执行结果维护重复失败计数：失败累加，成功清零（只清本指纹）。

        只清本指纹而不清全局：别的调用成功过，不代表这个仍在失败的调用已经
        解除循环——一起清掉会让循环更容易躲过判据（交替调用即可反复清零）。
        """
        key = self._fingerprint(tool, args)
        if result.ok:
            self._repeat_failures.pop(key, None)
            self._repeat_errors.pop(key, None)
            return
        self._repeat_failures[key] = self._repeat_failures.get(key, 0) + 1
        self._repeat_errors[key] = str(result.error or "")[:200]

    # ------------------------------------------------------------------
    # LLM 输出不可解析时的重试（R-40）
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_correction(exc: LLMOutputError) -> str:
        """回灌给模型的纠正提示：说清"你上一条输出无法解析"与正确形态。

        特意点名 XML/工具调用标签：真机上的那次不可解析输出正是
        `<｜｜DSML｜｜ invoke name="http_raw">` 这种形态，而 prompt 里从未允许过它。
        """
        raw = (exc.raw or "").strip()[:500]
        return (f"你上一条输出无法解析为 JSON（{exc}）。"
                "请严格只输出**一个 JSON 对象**：不要 markdown 代码块，"
                "不要 XML 或工具调用标签（如 <invoke>/<tool_call>），"
                "不要前后说明文字。两种格式二选一：\n"
                '{"thought": "推理", "tool": "工具名", "args": {...}}\n'
                '{"thought": "总结", "done": true, "summary": "结论", '
                '"evidence_refs": [证据seq]}\n'
                f"你上次的输出片段：{raw or '（空）'}")

    def _decide(self, messages: list[dict], mission_id: str, step: int,
                model: Optional[str] = None) -> dict:
        """调 LLM 取一步决策；输出不可解析时回灌纠正提示并重试（R-40）。

        重试**不消耗步数预算**：解析失败没有产生任何决策或工具调用，按步数
        记账等于替一次格式失误扣掉一步真实预算。每次失败都留一条证据
        （`phase=llm_parse_retry`，含原始输出片段），便于事后判断是模型形态
        失误还是端点问题；连续 `LLM_PARSE_RETRY_LIMIT` 次不可解析才抛出。

        调用失败（网络/HTTP/超时）不在此重试：那是 `LLMError` 而不是
        `LLMOutputError`，重试同一请求没有意义，直接向上抛给调用方收口。
        """
        for attempt in range(1, LLM_PARSE_RETRY_LIMIT + 2):
            try:
                return chat_json(self.llm, messages, model=model)
            except LLMOutputError as exc:
                self._append_evidence("decision", mission_id, step, {
                    "phase": "llm_parse_retry", "attempt": attempt,
                    "error": str(exc)[:300],
                    "raw": (exc.raw or "")[:800]})
                if attempt > LLM_PARSE_RETRY_LIMIT:
                    raise LLMError(
                        f"输出连续 {attempt} 次不可解析，放弃本次任务；"
                        f"最后一次: {str(exc).splitlines()[0]}") from exc
                messages.append({"role": "user",
                                 "content": self._parse_correction(exc)})
        raise LLMError("输出不可解析且重试逻辑异常终止")   # pragma: no cover

    def _mission_context(self, since_seq: int) -> str:
        """本任务期间观察到的工具输出原文（供按任务输出判定的判定器使用）。

        取自证据链中 seq 大于本任务起点的 tool_call 记录，天然按任务隔离，
        不会把历史任务的输出带进本次判定。
        """
        chunks = []
        for record in self.evidence.load():
            if record.seq <= since_seq or record.kind != "tool_call":
                continue
            output = str(record.content.get("output", "") or "")
            if output:
                chunks.append(output)
        return "\n".join(chunks)

    def _system_prompt(self, skills: list) -> str:
        """组装 system prompt：模式 persona 模板（无模式时用内核默认提示词）。

        工具 schema 来自已按模式过滤的注册表，被禁用的工具不会出现在
        提示词里——这是模式约束在提示词层的呈现，机制性拦截在注册表层。
        """
        template = (self.mode.read_system_prompt()
                    if self.mode is not None else SYSTEM_PROMPT)
        return template.replace(
            "{tools}", json.dumps(self.registry.schemas(),
                                  ensure_ascii=False)).replace(
            "{skills}", json.dumps([s.to_dict() for s in skills],
                                   ensure_ascii=False))

    def _tier_model(self, phase: str) -> Optional[str]:
        """按 budget.model_tier 解析本阶段决策用的模型 id。

        两级映射：阶段（recon/reason）-> 档位（cheap/strong）-> 模型 id
        （LLMConfig.tier_models，来自 PENTEST_LLM_MODEL_CHEAP/STRONG）。
        任一环节未声明/未配置都回落 None（= 主模型），零配置行为不变。
        常规决策步走 recon 档；预算耗尽后的强制收口走 reason 档
        （"超限换策略"的一部分：收口推理升级到更强模型）。
        """
        if self.mode is None:
            return None
        tier = self.mode.budget.model_tier.get(phase)
        if not tier:
            return None
        return self.llm.tier_models.get(tier) or None

    # ------------------------------------------------------------------
    def _emit(self, **event) -> None:
        """进度事件外发（fail-open）：观测通道坏了也绝不改任务语义。"""
        if self.on_event is None:
            return
        try:
            self.on_event(event)
        except Exception:  # noqa: BLE001 —— 故意 fail-open（与审计桥同哲学）
            pass

    def _finish(self, mission) -> "MissionResult":
        """收口统一出口：先发 done 事件再返回（run 内六个收口点共用）。"""
        self._emit(type="done", mission=mission.mission_id,
                   outcome=mission.outcome, steps=mission.steps)
        return mission

    def run(self, target: str, objective: str,
            fingerprint: str = "", stealth: bool = False) -> MissionResult:
        mission_id = self.memory.new_mission(target, objective)
        mission = MissionResult(mission_id=mission_id, target=target,
                                objective=objective)
        # 重复失败计数按任务重置："连续"指的是本任务内的连续
        self._repeat_failures = {}
        self._repeat_errors = {}
        self._repeat_blocks = {}
        skills = self.memory.find_skills(fingerprint or target)
        # 模式技能包过滤：mode.skills 声明之外的类别不注入（R-3）
        skills = self._filter_mode_skills(skills)
        skills = self._rank_skills(skills, fingerprint or target,
                                   stealth=stealth)
        mission.injected_skills = [s.title for s in skills[-3:]]
        self._used_skills = skills[-3:]   # 本次任务复用的技能（结果回写）
        self.verifier.reset()
        tail = self.evidence.tail()
        mission_start_seq = tail.seq if tail is not None else 0
        system = self._system_prompt(skills[-3:])
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": (
                f"目标: {target}\n目标特征: {fingerprint or '未知'}\n"
                f"任务: {objective}\n"
                f"当前时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")},
        ]
        self._emit(type="mission_start", mission=mission_id,
                   target=target, objective=objective)
        run_started = time.time()
        exhaust_reason = f"步数预算已用尽（max_steps={self.max_steps}）"
        time_exhausted = False

        for step in range(1, self.max_steps + 1):
            mission.steps = step
            # 时长预算：超限同样换策略而非硬退出——跳出循环进入强制收口
            if (self.max_minutes is not None
                    and (time.time() - run_started) / 60.0 >= self.max_minutes):
                exhaust_reason = (f"时长预算已用尽"
                                  f"（max_minutes={self.max_minutes} 分钟）")
                time_exhausted = True
                self._append_evidence("decision", mission_id, step, {
                    "phase": "budget_exhausted",
                    "thought": "时长预算耗尽，切换收口策略"})
                break
            try:
                decision = self._decide(messages, mission_id, step,
                                        self._tier_model("recon"))
            except LLMError as exc:
                mission.outcome = "failed"
                mission.summary = f"LLM 调用失败: {exc}"
                self.memory.finish(mission_id, mission.outcome,
                                   mission.summary)
                self._record_skill_outcomes(False)
                return self._finish(mission)

            self._append_evidence("decision", mission_id, step, {
                "thought": decision.get("thought", "")})

            if decision.get("done"):
                # 收口判定交给注入的 verifier（模式决定判据）：
                # 反幻觉校验是内核底线，任何判定器都先过这一关
                verdict = self.verifier.verify(
                    decision, self.evidence,
                    context=self._mission_context(mission_start_seq),
                    mission=mission_id)
                if not verdict.ok:
                    if verdict.retryable:
                        # 判定未过但可重试：回灌原因，让模型再试（不结束任务）
                        messages.append({"role": "user", "content":
                                         f"判定未通过: {verdict.reason}"})
                        continue
                    mission.outcome = "failed"
                    mission.summary = verdict.reason
                    self.memory.finish(mission_id, mission.outcome,
                                       mission.summary)
                    self._record_skill_outcomes(False)
                    return self._finish(mission)
                mission.outcome = "success"
                mission.summary = decision.get("summary", "")
                mission.evidence_refs = list(verdict.evidence_refs)
                # 判定器接受性：False = 正则命中但无 accept 留证（"未验证"，
                # 不判失败，只随结论落盘——报告与评分卡据此区分）
                mission.flag_verified = verdict.flag_verified
                self._append_evidence("conclusion", mission_id, step, {
                    "summary": mission.summary,
                    "evidence_refs": mission.evidence_refs,
                    "verdict": verdict.reason,
                    "flag_verified": verdict.flag_verified})
                self.memory.finish(mission_id, mission.outcome,
                                   evidence_refs=mission.evidence_refs,
                                   flag_verified=verdict.flag_verified)
                self._record_skill_outcomes(True)
                return self._finish(mission)

            tool = decision.get("tool", "")
            args = decision.get("args", {}) or {}
            # 模式参数冻结：命中 capability.constraints 的工具，在护栏裁决前
            # 就把冻结参数并进 args（后续裁决与执行、留证看到的都是实参）
            args = self.policy.apply_constraints(tool, args)
            spec = self.registry.get(tool)
            if spec is None:
                # 被模式 capability 禁用的工具已不在注册表：给出机制性
                # 拒绝的准确原因（而非笼统的"工具不存在"）
                if self.mode is not None \
                        and not self.mode.capability.allows(tool):
                    reason = (f"模式 {self.mode.id} 禁用该工具："
                              f"{self.mode.capability.denial_reason(tool)}")
                    messages.append(self._blocked(mission_id, step, tool,
                                                  args, reason, "deny"))
                    continue
                messages.append({"role": "user",
                                 "content": f"工具 {tool!r} 不存在，请重新选择"})
                continue
            allowed, reason = self.policy.check(tool, spec, args)
            if not allowed:
                messages.append(self._blocked(
                    mission_id, step, tool, args, reason,
                    self.policy.level_for(tool, spec)))
                continue

            # 内核侧重复失败检测（R-39）：同工具 + 同参数连续失败到阈值后，
            # 这一次不再执行——回灌纠正指令（含上次失败理由 + 换思路），
            # 留痕为 blocked（level=loop，与护栏拦截同一条审计口径）
            loop_reason = self._loop_reason(tool, args)
            if loop_reason:
                messages.append(self._blocked(mission_id, step, tool, args,
                                              loop_reason, "loop"))
                continue

            tool_result = self.registry.execute(tool, args)
            self._record_tool_outcome(tool, args, tool_result)
            record = self._append_evidence("tool_call", mission_id, step, {
                "tool": tool, "args": args, "ok": tool_result.ok,
                "output": str(tool_result.output)[:1500],
                "error": tool_result.error,
                # flag 候选 + 判定器结论（accept/reject）：接受性核对只看留证
                **oracle_evidence(tool, tool_result.output, args),
            })
            self.memory.add_step(mission_id, {
                "step": step, "tool": tool, "args": args,
                "ok": tool_result.ok, "output": str(tool_result.output)[:800],
                "evidence_seq": record.seq,
            })
            self._emit(type="step", mission=mission_id, step=step,
                       tool=tool, ok=tool_result.ok)
            messages.append({
                "role": "user",
                "content": (f"工具 {tool} 执行结果:\n"
                            f"{json.dumps(tool_result.to_dict(), ensure_ascii=False)[:2500]}")})

        # 预算（步数/时长）耗尽：不硬退出，换策略——追加一轮"强制收口"，
        # 要求模型停止工具调用、基于已有证据给出最终结论，再交判定器裁决
        if not time_exhausted:
            self._append_evidence("decision", mission_id, self.max_steps, {
                "phase": "budget_exhausted",
                "thought": "步数预算耗尽，切换收口策略"})
        messages.append({"role": "user", "content": (
            f"{exhaust_reason}。切换策略："
            "不要再调用任何工具，基于已获得的证据直接给出最终结论；"
            "若没有有效证据，如实说明任务未完成。")})
        try:
            decision = self._decide(messages, mission_id, self.max_steps,
                                    self._tier_model("reason"))
        except LLMError as exc:
            mission.outcome = "failed"
            mission.summary = f"步数预算耗尽且收口调用失败: {exc}"
            self.memory.finish(mission_id, mission.outcome, mission.summary)
            self._record_skill_outcomes(False)
            return self._finish(mission)

        verdict = self.verifier.verify(
            decision, self.evidence,
            context=self._mission_context(mission_start_seq))
        if decision.get("done") and verdict.ok:
            mission.outcome = "success"
            mission.summary = decision.get("summary", "")
            mission.evidence_refs = list(verdict.evidence_refs)
            self._append_evidence("conclusion", mission_id, self.max_steps, {
                "summary": mission.summary,
                "evidence_refs": mission.evidence_refs,
                "verdict": verdict.reason, "phase": "budget_concluded"})
            self.memory.finish(mission_id, mission.outcome,
                               evidence_refs=mission.evidence_refs)
            self._record_skill_outcomes(True)
            return self._finish(mission)

        mission.outcome = "failed"
        mission.summary = (f"{exhaust_reason}，"
                           f"切换收口策略后仍未通过判定: {verdict.reason}")
        self.memory.finish(mission_id, mission.outcome, mission.summary)
        self._record_skill_outcomes(False)
        return self._finish(mission)
