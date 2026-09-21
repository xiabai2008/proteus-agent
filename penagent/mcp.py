"""XPentest MCP Server：把渗透 Agent 能力暴露为 MCP 工具（stdio，零依赖）。

MCP 工具（供外部 Agent 客户端调用）：
- 底层工具：port_scan / http_probe / dns_lookup / robots_fetch（安全被动）
           + poxiao_scan（危险，需 authorize=true）
- 高层能力：pentest_run（LLM 决策完整任务）/ pentest_skills / pentest_missions
           / pentest_reflect

协议：JSON-RPC 2.0 over stdio（initialize / tools/list / tools/call）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from penagent.agent import PenAgent, Policy
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.memory import Memory
from penagent.policy_gate import PolicyGate
from penagent.reflect import Reflector
from penagent.registry import ToolCenter, build_center
from penagent.tools import ToolSpec

MCP_VERSION = "2025-06-18"

# 服务端高层能力：只暴露给 MCP 客户端，不进入内核 ReAct 循环
SERVER_TOOLS = [
    ToolSpec(name="pentest_run",
             description="执行完整渗透/CTF 任务（LLM 决策循环），返回总结与证据引用。"
                         "mode 指定模式档案：pentest-standard（常规渗透与侦察）/"
                         "ctf-web / ctf-crypto（CTF 与解题任务选 ctf-*）——"
                         "决定工具白名单、权限档位、预算与判定器；"
                         "省略时使用服务端配置的默认模式（未配置则不加模式约束）。"
                         "危险动作需 authorize=true。",
             parameters={"target": {"type": "string"},
                         "objective": {"type": "string"},
                         "mode": {"type": "string"},
                         "authorize": {"type": "boolean"}}),
    ToolSpec(name="pentest_skills",
             description="列出经验库技能（按成功率排序）",
             parameters={}),
    ToolSpec(name="pentest_missions",
             description="列出作战记录",
             parameters={}),
    ToolSpec(name="pentest_reflect",
             description="对指定任务反思并沉淀技能",
             parameters={"mission_id": {"type": "string"}}),
]


class PentestMCPServer:
    """MCP Server：工具注册表 + Agent 高层能力。"""

    def __init__(self, data_dir: str = "data",
                 allowed_targets: Optional[list[str]] = None,
                 center: Optional[ToolCenter] = None,
                 authorize: bool = False,
                 default_mode: str = "") -> None:
        self.data_dir = data_dir
        # 授权目标与高危授权：服务端级（操作员给），不来自调用参数。
        # 目标规范化必须做：CLI 的 --targets 是 "a,b" 字符串，直接 list() 会
        # 炸成单字符、把白名单打成筛子（见 Policy.normalize_targets）
        self.allowed_targets = Policy.normalize_targets(allowed_targets)
        self.authorize = bool(authorize)
        # 工具清单统一来自注册中心：内置 function + external_tools.json 的 CLI
        # + 已发现的 MCP server 工具（discover_mcp 前不连接任何外部服务）
        self.center = center or build_center()
        self.center.register_server_tools(SERVER_TOOLS)
        self.registry = self.center.build_registry()
        # 闸门挂在注册表上：MCP 底层工具入口此前直连注册表、不过 Policy，
        # 于是 --targets 白名单形同虚设（越界目标照常执行，见
        # docs/DSH宿主实测记录.md F1）。挂上之后越界目标与未授权高危工具
        # 在工具体执行前就被拒，且任何调用方都绕不过去。
        self.policy = Policy(allowed_targets=self.allowed_targets or None,
                             authorize=self.authorize)
        self.registry.gate = PolicyGate(self.policy)
        self.memory = Memory(data_dir)
        self.evidence = EvidenceChain(Path(data_dir) / "chain.jsonl")
        self.llm = LLMConfig.from_env()
        # 服务端级默认模式：pentest_run 未显式指定 mode 时的回落。
        # 空串 = 保持向后兼容（无模式路径：全量注册表 + 证据链判定器）；
        # 非空时**构造期即校验**存在性——配错模式名在启动时大声失败，
        # 而不是等第一次任务才报（fail-closed，与 modes.py 加载即校验一致）。
        self.default_mode = ""
        self._default_profile = None
        if default_mode:
            from penagent.modes import load_mode

            self._default_profile = load_mode(default_mode)
            self.default_mode = default_mode

    # ------------------------------------------------------------------
    def _agent(self, authorize: bool = False,
               mode_id: str = "") -> PenAgent:
        """内层 ReAct Agent：复用服务端授权目标，按调用参数放大授权与选择模式。

        `--targets` 对 pentest_run 同样生效（此前被 `allowed_targets=None`
        丢掉，只剩默认回环）；`authorize` 是 pentest_run 的既有契约
        （工具描述里写明"危险动作需 authorize=true"），但只在这条路径上生效，
        且作用范围是**本次任务的注册表副本**——不改动服务端共享注册表。
        `mode_id` 非空时按模式档案构建注册表（capability 白名单 / 沙箱档位 /
        判定器 / 预算随之切换），未知 id 抛 ModeError 由调用方转 isError。
        `mode_id` 为空且服务端配了 `default_mode` 时回落到该默认模式（R-1）；
        两者皆无则走无模式路径（向后兼容）。
        """
        mode = None
        if mode_id:
            from penagent.modes import load_mode

            mode = load_mode(mode_id)
        elif self._default_profile is not None:
            # 未显式指定 mode：回落到服务端默认模式（R-1）。
            # 不做这层回落时，不带 mode 的任务走 mode=None 分支——
            # 沙箱裁决缺失（危险 CLI 工具直跑宿主）、记忆落 default 分区、
            # 步数预算退回 12，等于模式约束完全失效（违反硬规则 1）。
            mode = self._default_profile
        policy = Policy(allowed_targets=self.allowed_targets or None,
                        authorize=bool(authorize) or self.authorize,
                        mode=mode)
        if mode is not None:
            registry = self.center.build_registry(mode)
        else:
            registry = self.registry.copy(gate=PolicyGate(policy))
        registry.gate = PolicyGate(policy)
        return PenAgent(registry, self.memory, self.evidence,
                        self.llm, policy, max_steps=None, mode=mode)

    # ------------------------------------------------------------------
    # MCP tools 定义
    def _tools_schema(self) -> list[dict]:
        """按 MCP 规范导出工具清单：name / description / inputSchema。

        官方 SDK 客户端会严格校验报文——缺 inputSchema 会整份列表解析失败，
        结果是一个工具都注册不上（DSH 的 mcp-client 即如此）。所以这里只吐
        规范字段：内核侧的 dangerous 标记映射到 annotations.destructiveHint，
        非规范的 parameters 不再外泄。
        """
        tools = []
        for schema in self.center.schemas():
            tool = {
                "name": schema["name"],
                "description": schema.get("description", ""),
                "inputSchema": {"type": "object",
                                "properties": schema.get("parameters") or {}},
            }
            if schema.get("dangerous"):
                tool["annotations"] = {"destructiveHint": True}
            tools.append(tool)
        return tools

    # ------------------------------------------------------------------
    def handle_line(self, line: str) -> Optional[str]:
        """处理一行 JSON-RPC 消息，返回响应行（通知返回 None）。"""
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return json.dumps({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32700,
                                         "message": "非法 JSON"}})
        msg_id = msg.get("id")
        method = msg.get("method", "")

        if method == "initialize":
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {
                "protocolVersion": MCP_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "xpentest",
                               "version": "0.1.0"}}})
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "tools/list":
            return json.dumps({"jsonrpc": "2.0", "id": msg_id,
                               "result": {"tools": self._tools_schema()}})
        if method == "tools/call":
            return json.dumps(self._handle_call(msg_id,
                                                msg.get("params") or {}))
        return json.dumps({"jsonrpc": "2.0", "id": msg_id,
                           "error": {"code": -32601,
                                     "message": f"不支持的方法: {method}"}})

    # ------------------------------------------------------------------
    def _handle_call(self, msg_id, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments") or {}
        try:
            if name == "pentest_run":
                result = self._agent(authorize=bool(args.get("authorize")),
                                     mode_id=str(args.get("mode") or ""))\
                    .run(args.get("target", ""), args.get("objective", ""))
                return self._result(msg_id, result.to_dict(),
                                    is_error=result.outcome != "success")
            if name == "pentest_skills":
                skills = self.memory.list_skills(sort_by_rate=True)
                return self._result(msg_id, [s.to_dict() for s in skills])
            if name == "pentest_missions":
                return self._result(msg_id, self.memory.list_missions())
            if name == "pentest_reflect":
                analysis, skill = Reflector(self.llm).reflect(
                    args.get("mission_id", ""), self.memory, self.evidence)
                return self._result(msg_id, {
                    "analysis": analysis,
                    "skill": skill.to_dict() if skill else None})
            # 底层工具
            tool_result = self.registry.execute(name, args)
            # 底层工具失败（含被闸门/沙箱拒绝）一律 isError=true
            return self._result(msg_id, tool_result.to_dict(),
                                is_error=not tool_result.ok)
        except Exception as exc:
            # 工具执行异常按 MCP 规范走 isError=true 的结构化结果，而不是
            # 协议级 error——协议错误该留给非法请求（未知方法等）
            return self._result(msg_id, {"ok": False, "error": str(exc)},
                                is_error=True)

    @staticmethod
    def _result(msg_id, content, is_error: bool = False) -> dict:
        """工具调用结果：按 MCP 规范包成 content 块数组（文本载 JSON）。

        规范要求 content 是内容块数组、失败在 isError 上表达；直接回吐裸
        对象会让严格客户端（官方 SDK）解析失败。
        """
        text = (content if isinstance(content, str)
                else json.dumps(content, ensure_ascii=False))
        return {"jsonrpc": "2.0", "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}],
                           "isError": is_error}}

    # ------------------------------------------------------------------
    def serve_stdio(self) -> None:
        """stdio 传输：逐行读 stdin，响应写 stdout（强制 UTF-8）。"""
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            resp = self.handle_line(line)
            if resp is not None:
                sys.stdout.write(resp + "\n")
                sys.stdout.flush()
