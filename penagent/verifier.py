"""成功判定器（Verifier）：由模式决定"什么算成功"。

- EvidenceChainVerifier（渗透模式）：结论必须引用真实存在的证据链记录，
  包装 evidence.valid_refs 的引用校验，语义不削弱（硬规则 2）。
- FlagRegexVerifier（CTF 模式）：按 flag 正则判定任务输出，命中即收口，
  未命中的 auto_retry 次内允许回灌原因重试再判定。

反幻觉底线由基类统一执行：任何模式、任何判定器，结论引用不存在的证据
一律判失败，且不给重试——这是内核不变量，不是模式可调项。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VerificationResult:
    """判定结果：ok=False 且 retryable=True 时，主循环可重试再判定。"""

    ok: bool
    reason: str = ""
    retryable: bool = False
    evidence_refs: tuple[int, ...] = ()


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

    def reset(self) -> None:
        """任务开始前清零判定计数（同一实例可跨任务复用）。"""
        self._attempts = 0

    @property
    def attempts(self) -> int:
        return self._attempts

    def verify(self, decision: dict, evidence,
               context: str = "") -> VerificationResult:
        """判定一次任务收口。

        context：本任务期间观察到的原文（如工具输出），供按任务输出判定的
        判定器使用；不参与证据引用校验。
        """
        self._attempts += 1
        valid_refs, invalid = _check_refs(decision, evidence)
        if invalid:
            # 硬规则 2：编造证据引用必须判失败，且不给重试机会
            return VerificationResult(
                False, f"反幻觉拦截：结论引用 {invalid} 条不存在的证据",
                retryable=False)
        ok, reason = self._judge(decision, evidence, context)
        if ok:
            return VerificationResult(True, reason, evidence_refs=valid_refs)
        return VerificationResult(False, reason,
                                  retryable=self._attempts <= self.auto_retry,
                                  evidence_refs=valid_refs)

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
        if match:
            return True, f"flag 命中: {match.group(0)}"
        left = self.auto_retry - (self._attempts - 1)
        if left > 0:
            return False, (f"未命中 flag 正则 {self.pattern!r}，"
                           f"剩余重试 {left} 次")
        return False, f"未命中 flag 正则 {self.pattern!r}（重试已耗尽）"


def build_verifier(spec) -> Verifier:
    """按模式档案的 verifier 段构造判定器（模式与实现解耦）。"""
    if getattr(spec, "type", "") == "flag_regex":
        return FlagRegexVerifier(pattern=spec.pattern,
                                 auto_retry=spec.auto_retry)
    return EvidenceChainVerifier(require_poc=bool(getattr(spec, "require_poc",
                                                         False)),
                                 auto_retry=getattr(spec, "auto_retry", 0))
