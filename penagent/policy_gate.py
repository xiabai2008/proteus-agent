"""工具执行闸门（Policy Gate）：目标白名单 + 高危授权 + 协议白名单。

**为什么要有它**：升级前"目标白名单校验 + 高危授权"只在 `PenAgent.run` 里
调用 `policy.check()`（`penagent/agent.py`），而 MCP server 的底层工具分支
直连 `registry.execute()`、Web/子进程各走各的，于是 `--targets` 白名单形同
虚设。实测（docs/DSH宿主实测记录.md F1）：`--targets 127.0.0.1` 起服务后，
`port_scan` 传 `127.0.0.2` 与 `192.168.1.1` 都照常执行并真实发起连接。

**实现方式与 `SandboxPolicy` 同构**：闸门由 `ToolRegistry` 持有，裁决发生在
`execute()` 内部、工具体被调用之前——任何调用方（ReAct 循环 / MCP server /
Web / CLI 子进程）都绕不过去，而不是靠调用方自觉（硬规则 1/3）。

**授权来源**：`authorize` 只来自持有闸门的一方（操作员），**不看调用参数**。
调用参数里的 `authorize` 一律不生效——否则模型可以给自己盖章放行。
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Optional, Protocol

# 协议白名单：与 mcp_client.ALLOWED_SCHEMES、llm.ALLOWED_SCHEMES 同一约定
ALLOWED_SCHEMES = ("http", "https")

# 会承载目标的参数名：这些键的值要过白名单
TARGET_KEYS = ("host", "url", "domain", "target", "base_url")


class _PolicyLike(Protocol):
    """闸门只需要 Policy 的两个方法（避免与 agent.py 循环导入）。"""

    def check(self, tool: str, spec, args: dict) -> tuple[bool, str]: ...

    def level_for(self, tool: str, spec=None) -> str: ...


@dataclass(frozen=True)
class GateDecision:
    """一次执行前的闸门裁决。"""

    allowed: bool
    reason: str = ""
    rule: str = ""            # scheme | allowlist | dangerous | mode | policy
    level: str = "ok"         # ok | ask | deny（供审计与审批展示）


class PolicyGate:
    """按 (spec, args) 裁决是否放行一次工具执行。"""

    def __init__(self, policy: _PolicyLike) -> None:
        self.policy = policy

    # ------------------------------------------------------------------
    def check(self, spec, args: Optional[dict] = None) -> GateDecision:
        args = args or {}
        reason = self._scheme_reason(args)
        if reason:
            return GateDecision(False, reason, "scheme", "deny")

        allowed, detail = self.policy.check(spec.name, spec, args)
        if not allowed:
            return GateDecision(False, detail, self._rule_of(detail),
                                self._level(spec))
        return GateDecision(True, "", "", self._level(spec))

    # ------------------------------------------------------------------
    @staticmethod
    def _scheme_reason(args: dict) -> str:
        """协议白名单：带 scheme 的目标值只允许 http/https。

        值不带 "://"（如 bare host `127.0.0.1`）时不在这里判，交给白名单裁决。
        """
        for key in TARGET_KEYS:
            value = args.get(key)
            if not isinstance(value, str) or "://" not in value:
                continue
            scheme = urllib.parse.urlparse(value).scheme.lower()
            if scheme and scheme not in ALLOWED_SCHEMES:
                return (f"目标协议不被允许: {scheme!r}"
                        f"（仅 {'/'.join(ALLOWED_SCHEMES)}）")
        return ""

    @staticmethod
    def _rule_of(reason: str) -> str:
        """把 Policy 的拒绝理由归类（仅用于审计标签，判定以理由原文为准）。"""
        if "不在授权范围" in reason:
            return "allowlist"
        if "未授权" in reason:
            return "dangerous"
        if "禁用" in reason or "档位" in reason:
            return "mode"
        return "policy"

    def _level(self, spec) -> str:
        try:
            return self.policy.level_for(spec.name, spec)
        except Exception:                              # noqa: BLE001
            return "ok"
