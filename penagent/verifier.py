"""成功判定器（Verifier）：由模式决定"什么算成功"。

- EvidenceChainVerifier（渗透模式）：结论必须引用真实存在的证据链记录，
  包装 evidence.valid_refs 的引用校验，语义不削弱（硬规则 2）。
- FlagRegexVerifier（CTF 模式）：按 flag 正则判定任务输出，命中即收口，
  未命中的 auto_retry 次内允许回灌原因重试再判定；命中后再做一次
  **判定器（oracle）接受性核对**——见下。

反幻觉底线由基类统一执行：任何模式、任何判定器，结论引用不存在的证据
一律判失败，且不给重试——这是内核不变量，不是模式可调项。

**判定器接受性（oracle gate，2026-09-27 拍板）**：flag 正则只证明"格式像 flag"，
证明不了"题目自己的 checker 接受它"——一次实测里模型正是交了一个正则命中、
真机判定器返回 0 的 flag（并把它解释成"作者埋了死路"）。因此命中后再查证据链：
有没有一条 `native_emu` 的 accept 记录含这个字符串。有 → 标注"判定器已接受"；
没有 → 标注"未验证"。**未验证不判失败**（拍板：先标注，不改判定口径），
但结论文案与任务记录都带上它，报告与评分卡据此区分"解出"与"自称解出"。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

#: 判定器（oracle）工具：输出里带结构化 `verdict` 的工具。CTF 里只有
#: `native_emu`（真机执行题目自带 checker）能对 flag 说 accept/reject。
ORACLE_TOOLS: tuple[str, ...] = ("native_emu",)

#: 从文本里捞 flag 候选的通用正则（与 CTF 模式默认判定正则同形）
_FLAG_RE = re.compile(r"(?i)(flag|ctf)\{[^}]{1,200}\}")


@dataclass(frozen=True)
class VerificationResult:
    """判定结果：ok=False 且 retryable=True 时，主循环可重试再判定。"""

    ok: bool
    reason: str = ""
    retryable: bool = False
    evidence_refs: tuple[int, ...] = ()
    #: CTF 判定器专用：该 flag 是否被判定器接受过。
    #: None = 不适用（渗透判定器）；True/False = 已核对（False 即"未验证"，
    #: 按拍板**不改变 ok**，只作标注）。
    flag_verified: Optional[bool] = None


def flags_in_text(text, limit: int = 5) -> list[str]:
    """文本里的 flag 候选：去重、保序、限量（留证与接受性核对共用）。"""
    out: list[str] = []
    for match in _FLAG_RE.finditer(str(text or "")):
        value = match.group(0)
        if value not in out:
            out.append(value)
        if len(out) >= max(1, int(limit)):
            break
    return out


def oracle_evidence(tool: str, output, args=None) -> dict:
    """工具执行层的留证补充：flag 候选 + 判定器结论。

    - `flags`：从**参数与输出**里捞到的 flag 候选（限量 5 条）——让"这个 flag
      出现过吗 / 被接受过吗"可机检，而不必在链里存整段载荷（链的既有口径是
      只记调用元数据，这里只放开"flag 字符串"这一类）；
    - `oracle`：判定器工具的结构化结论（accept/reject）。
    """
    fields: dict = {}
    flags: list[str] = []
    if args:
        flags = flags_in_text(json.dumps(args, ensure_ascii=False))
    for extra in flags_in_text(output):
        if extra not in flags:
            flags.append(extra)
    if flags:
        fields["flags"] = flags[:5]
    if tool in ORACLE_TOOLS:
        verdict = ""
        if isinstance(output, dict):
            verdict = str(output.get("verdict") or "")
        elif isinstance(output, str):
            found = re.search(r'"verdict"\s*:\s*"(accept|reject)"', output)
            verdict = found.group(1) if found else ""
        if verdict in ("accept", "reject"):
            fields["oracle"] = verdict
    return fields


def oracle_accepts(flag: str, evidence, mission: str = "") -> bool:
    """证据链里是否存在"判定器接受了这个 flag"的记录。

    判据落在**留证**上而不是模型自述：`tool_call` 记录里 `oracle == "accept"`
    且 `flags` 含该字符串（记录由工具执行层写入，见 mcp.py / agent.py）。
    `mission` 非空时只看该任务的记录——否则上一单任务的 accept 会替下一单背书。
    """
    target = str(flag or "")
    if not target:
        return False
    for record in evidence.load():
        if record.kind != "tool_call":
            continue
        content = record.content or {}
        if mission and content.get("mission") != mission:
            continue
        if content.get("oracle") != "accept":
            continue
        if target in (content.get("flags") or []):
            return True
    return False


def oracle_facts(evidence, mission: str = "") -> dict:
    """按任务汇总 flag 事实：出现过哪些、哪些被判定器接受。

    供 `report_gen` 给宿主路径的报告标注 `flag_verified`——宿主会话的结论不
    经内核判定器（R-45 未闭环），至少要能机检"报告里的 flag 有没有判定器背书"。
    """
    seen: list[str] = []
    accepted: list[str] = []
    for record in evidence.load():
        if record.kind != "tool_call":
            continue
        content = record.content or {}
        if mission and content.get("mission") != mission:
            continue
        for flag in content.get("flags") or []:
            if flag not in seen:
                seen.append(flag)
            if content.get("oracle") == "accept" and flag not in accepted:
                accepted.append(flag)
    return {"flags_seen": seen, "flags_accepted": accepted,
            "flag_verified": bool(accepted)}


def _check_refs(decision: dict, evidence) -> tuple[tuple[int, ...], int]:
    """反幻觉校验：返回 (有效引用, 不存在的引用条数)。

    非法引用值（非整数）按"不存在"计，不做静默丢弃——丢弃等于放宽校验。
    """
    raw = decision.get("evidence_refs") or []
    refs: list[int] = []
    for item in raw:
        try:
            refs.append(int(item))
        except (TypeError, ValueError):
            refs.append(-1)
    if not refs:
        return (), 0
    valid = tuple(evidence.valid_refs(refs))
    return valid, len(refs) - len(valid)


class Verifier:
    """成功判定器接口。

    每次 verify() 记一次判定；失败且 retryable=True 时主循环可回灌原因让
    模型重试，最多 auto_retry 次（即最多 auto_retry+1 次判定），耗尽判失败。
    """

    type = "base"

    def __init__(self, auto_retry: int = 0) -> None:
        self.auto_retry = max(0, int(auto_retry or 0))
        self._attempts = 0
        #: 判定器接受性（子类在 _judge 里设置；None = 不适用）
        self.flag_verified: Optional[bool] = None
        self._mission = ""

    def reset(self) -> None:
        """任务开始前清零判定计数（同一实例可跨任务复用）。"""
        self._attempts = 0
        self.flag_verified = None
        self._mission = ""

    @property
    def attempts(self) -> int:
        return self._attempts

    def verify(self, decision: dict, evidence,
               context: str = "", mission: str = "") -> VerificationResult:
        """判定一次任务收口。

        context：本任务期间观察到的原文（如工具输出），供按任务输出判定的
        判定器使用；不参与证据引用校验。
        mission：任务 id，供判定器做**接受性核对**（只看本任务的留证）。
        """
        self._attempts += 1
        self._mission = str(mission or "")
        self.flag_verified = None
        valid_refs, invalid = _check_refs(decision, evidence)
        if invalid:
            # 硬规则 2：编造证据引用必须判失败，且不给重试机会
            return VerificationResult(
                False, f"反幻觉拦截：结论引用 {invalid} 条不存在的证据",
                retryable=False)
        ok, reason = self._judge(decision, evidence, context)
        if ok:
            return VerificationResult(True, reason, evidence_refs=valid_refs,
                                      flag_verified=self.flag_verified)
        return VerificationResult(False, reason,
                                  retryable=self._attempts <= self.auto_retry,
                                  evidence_refs=valid_refs,
                                  flag_verified=self.flag_verified)

    def _judge(self, decision: dict, evidence,
               context: str) -> tuple[bool, str]:
        raise NotImplementedError


class EvidenceChainVerifier(Verifier):
    """渗透模式判定：结论须引用真实证据；可选要求必须带 PoC 引用。"""

    type = "evidence_chain"

    def __init__(self, require_poc: bool = False, auto_retry: int = 0) -> None:
        super().__init__(auto_retry=auto_retry)
        self.require_poc = bool(require_poc)

    def _judge(self, decision: dict, evidence,
               context: str) -> tuple[bool, str]:
        if self.require_poc and not (decision.get("evidence_refs") or []):
            return False, "结论缺少可复现证据引用（模式要求 require_poc）"
        return True, "证据链校验通过"


class FlagRegexVerifier(Verifier):
    """CTF 模式判定：按 flag 正则匹配任务输出（结论 or 任务期间的工具输出）。"""

    type = "flag_regex"

    def __init__(self, pattern: str, auto_retry: int = 0) -> None:
        super().__init__(auto_retry=auto_retry)
        if not pattern:
            raise ValueError("FlagRegexVerifier 需要 pattern")
        self.pattern = pattern
        self._regex = re.compile(pattern)

    def _corpus(self, decision: dict, context: str) -> str:
        summary = str(decision.get("summary", "") or "")
        return f"{summary}\n{context}" if context else summary

    def _judge(self, decision: dict, evidence,
               context: str) -> tuple[bool, str]:
        match = self._regex.search(self._corpus(decision, context))
        if not match:
            left = self.auto_retry - (self._attempts - 1)
            if left > 0:
                return False, (f"未命中 flag 正则 {self.pattern!r}，"
                               f"剩余重试 {left} 次")
            return False, f"未命中 flag 正则 {self.pattern!r}（重试已耗尽）"
        # 命中格式后做接受性核对（判定器 gate）：有 accept 留证才算"已验证"。
        # 未验证**不判失败**（2026-09-27 拍板：只标注，不改判定口径），
        # 但文案与任务记录都带出来——报告/评分卡据此区分"解出"与"自称解出"。
        flag = match.group(0)
        accepted = oracle_accepts(flag, evidence, mission=self._mission)
        self.flag_verified = accepted
        if accepted:
            return True, f"flag 命中: {flag}（判定器已接受）"
        return True, (f"flag 命中: {flag}（未验证：证据链里没有判定器"
                      f"（{'/'.join(ORACLE_TOOLS)}）接受该 flag 的记录）")


def build_verifier(spec) -> Verifier:
    """按模式档案的 verifier 段构造判定器（模式与实现解耦）。"""
    if getattr(spec, "type", "") == "flag_regex":
        return FlagRegexVerifier(pattern=spec.pattern,
                                 auto_retry=spec.auto_retry)
    return EvidenceChainVerifier(require_poc=bool(getattr(spec, "require_poc",
                                                         False)),
                                 auto_retry=getattr(spec, "auto_retry", 0))
