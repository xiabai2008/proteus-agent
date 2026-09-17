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
from penagent.builtin_tools import register_builtins
from penagent.evidence import EvidenceChain
from penagent.external_tools import load_external_tools
from penagent.llm import LLMConfig
from penagent.memory import Memory
from penagent.reflect import Reflector
from penagent.tools import ToolRegistry

MCP_VERSION = "2025-06-18"


class PentestMCPServer:
    """MCP Server：工具注册表 + Agent 高层能力。"""

    def __init__(self, data_dir: str = "data",
                 allowed_targets: Optional[list[str]] = None) -> None:
        self.data_dir = data_dir
        self.registry = ToolRegistry()
        register_builtins(self.registry)
        load_external_tools(self.registry)
        self.memory = Memory(data_dir)
        self.evidence = EvidenceChain(Path(data_dir) / "chain.jsonl")
        self.llm = LLMConfig.from_env()
        self.policy = Policy(allowed_targets=allowed_targets or None)
        self._agents: dict[str, PenAgent] = {}

    # ------------------------------------------------------------------
    def _agent(self, authorize: bool = False) -> PenAgent:
        return PenAgent(self.registry, self.memory, self.evidence,
                        self.llm, Policy(allowed_targets=None,
                                         authorize=authorize),
                        max_steps=12)

    # ------------------------------------------------------------------
    # MCP tools 定义
    def _tools_schema(self) -> list[dict]:
        tools = [t.to_schema() for t in self.registry._tools.values()]
        tools += [
            {"name": "pentest_run",
             "description": "执行完整渗透任务（LLM 决策循环：侦察/扫描/利用），"
                            "返回总结与证据引用。危险动作需 authorize=true。",
             "parameters": {"target": {"type": "string"},
                            "objective": {"type": "string"},
                            "authorize": {"type": "boolean"}}},
            {"name": "pentest_skills",
             "description": "列出经验库技能（按成功率排序）",
             "parameters": {}},
            {"name": "pentest_missions",
             "description": "列出作战记录",
             "parameters": {}},
            {"name": "pentest_reflect",
             "description": "对指定任务反思并沉淀技能",
             "parameters": {"mission_id": {"type": "string"}}},
        ]
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
                result = self._agent(authorize=bool(args.get("authorize")))\
                    .run(args.get("target", ""), args.get("objective", ""))
                return self._result(msg_id, result.to_dict())
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
            return self._result(msg_id, tool_result.to_dict())
        except Exception as exc:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32603, "message": str(exc)}}

    @staticmethod
    def _result(msg_id, content) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id,
                "result": {"content": content}}

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
