"""外部 MCP Server 客户端（stdio / streamable-http 双传输，零新依赖）。

与 penagent/mcp.py（本内核作为 MCP Server）方向相反：这里是把外部已有的
MCP Server（RayScan / Chameleon 等）当工具源接进来。

协议：JSON-RPC 2.0（initialize / notifications/initialized / tools/list /
tools/call）。两种传输：
- stdio：拉起子进程，按行读写；进程用完即杀，不留常驻。
- http：POST 单条 JSON-RPC，兼容 application/json 与 SSE(text/event-stream)
  两种响应；initialize 返回的 Mcp-Session-Id 会在后续请求回带。

地址边界：MCP 端点来自本机配置（penagent/mcp_servers.json），默认指向
回环地址——本地 MCP Server 本来就跑在回环上，因此这里**不做私网/回环阻断**
（那会把正当用法一并打死），而是限制协议为 http/https、禁止跟随重定向
（重定向意味着配置错误或中间人，宁可报错也不把会话 id 带去别的地址）。

超时与失败处理：任何一步超时都干净杀掉子进程并抛 MCPClientError，
由注册中心决定"不可用即不注册"（不静默降级）。
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "xpentest", "version": "0.1.0"}
ALLOWED_SCHEMES = ("http", "https")


class MCPClientError(RuntimeError):
    """外部 MCP Server 不可达或协议出错。"""


def validate_http_url(url: str) -> Optional[str]:
    """协议与地址边界校验：只允许 http/https 且必须带主机名。

    返回不可用原因（None = 通过）。
    """
    if not url:
        return "未配置服务地址 url"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return f"非法协议 {parsed.scheme!r}（仅允许 http/https）"
    if not parsed.hostname:
        return f"地址缺少主机名: {url!r}"
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """拒绝跟随重定向（MCP 端点应是固定地址）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class MCPServerSpec:
    """外部 MCP Server 声明（声明式，不触发任何 I/O）。"""

    name: str
    transport: str = "stdio"            # stdio | http
    command: tuple[str, ...] = ()       # stdio：启动命令
    url: str = ""                       # http：服务地址（streamable-http）
    workdir: str = ""
    pythonpath: str = ""                # stdio：附加 PYTHONPATH（src 布局项目）
    timeout: float = 30.0
    description: str = ""
    modes: tuple[str, ...] = ()         # 模式可用性（空 = 全模式）
    dangerous: bool = False             # 本 server 的工具默认是否高危
    tool_overrides: dict = field(default_factory=dict)   # 按远端工具名覆盖

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "MCPServerSpec":
        return cls(
            name=name,
            transport=str(data.get("transport", "stdio")),
            command=tuple(data.get("command") or ()),
            url=str(data.get("url", "") or ""),
            workdir=str(data.get("workdir", "") or ""),
            pythonpath=str(data.get("pythonpath", "") or ""),
            timeout=float(data.get("timeout", 30.0)),
            description=str(data.get("description", "") or ""),
            modes=tuple(data.get("modes") or ()),
            dangerous=bool(data.get("dangerous", False)),
            tool_overrides=dict(data.get("tool_overrides") or {}),
        )

    def availability(self) -> Optional[str]:
        """本地可用性预检：返回不可用原因（None = 可尝试连接）。"""
        if self.transport == "stdio":
            if not self.command:
                return "未配置启动命令"
            import shutil
            from pathlib import Path

            first = self.command[0]
            if not Path(first).exists() and shutil.which(first) is None:
                return f"可执行文件不存在: {first}"
            return None
        if self.transport == "http":
            return validate_http_url(self.url)
        return f"未知传输方式: {self.transport}"


def _content_text(result: Any) -> str:
    """MCP tools/call 结果 -> 文本（优先取 text 内容块）。"""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        blocks = result.get("content")
        if isinstance(blocks, list):
            texts = [b.get("text", "") for b in blocks
                     if isinstance(b, dict) and b.get("type") == "text"]
            if texts:
                return "\n".join(texts)
        return json.dumps(result, ensure_ascii=False)[:4000]
    return str(result)


def _parse_payload(raw: str) -> dict:
    """解析响应体：JSON 或 SSE(data: 行) 两种形态。"""
    text = raw.strip()
    if text.startswith("{"):
        return json.loads(text)
    for line in text.splitlines():
        if line.startswith("data:"):
            chunk = line[5:].strip()
            if chunk and chunk != "[DONE]":
                return json.loads(chunk)
    raise MCPClientError(f"无法解析 MCP 响应: {raw[:200]!r}")


class MCPClient:
    """会话式客户端：进入上下文（connect）后 list_tools / call_tool。"""

    def __init__(self, spec: MCPServerSpec) -> None:
        self.spec = spec
        self._proc: Optional[subprocess.Popen] = None
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._next_id = 0
        self._session_id = ""

    # ------------------------------------------------------------------
    def __enter__(self) -> "MCPClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> "MCPClient":
        reason = self.spec.availability()
        if reason:
            raise MCPClientError(f"{self.spec.name} 不可用: {reason}")
        if self.spec.transport == "stdio":
            self._spawn()
        self._rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        })
        self._notify("notifications/initialized", {})
        return self

    def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # ------------------------------------------------------------------
    def list_tools(self) -> list[dict]:
        result = self._rpc("tools/list", {})
        tools = result.get("tools") if isinstance(result, dict) else None
        return list(tools or [])

    def call_tool(self, name: str, arguments: dict) -> str:
        result = self._rpc("tools/call", {"name": name,
                                          "arguments": arguments or {}})
        if isinstance(result, dict) and result.get("isError"):
            raise MCPClientError(f"{self.spec.name}.{name} 执行失败: "
                                 f"{_content_text(result)[:300]}")
        return _content_text(result)

    # ------------------------------------------------------------------
    # stdio 传输
    def _spawn(self) -> None:
        env = dict(os.environ)
        if self.spec.pythonpath:
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (f"{self.spec.pythonpath}{os.pathsep}{existing}"
                                 if existing else self.spec.pythonpath)
        try:
            self._proc = subprocess.Popen(
                list(self.spec.command), cwd=self.spec.workdir or None,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, encoding="utf-8",
                errors="replace", env=env, bufsize=1)
        except OSError as exc:
            raise MCPClientError(
                f"{self.spec.name} 启动失败: {exc}") from exc
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        for line in self._proc.stdout:
            self._queue.put(line)

    def _read_response(self, msg_id: int) -> dict:
        import time

        deadline = time.monotonic() + self.spec.timeout
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                self.close()
                raise MCPClientError(
                    f"{self.spec.name} 响应超时（{self.spec.timeout}s）")
            try:
                line = self._queue.get(timeout=remain)
            except queue.Empty:
                self.close()
                raise MCPClientError(
                    f"{self.spec.name} 响应超时（{self.spec.timeout}s）")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue          # 忽略非协议输出（日志等）
            if msg.get("id") != msg_id:
                continue          # 通知或他人响应
            if "error" in msg:
                raise MCPClientError(
                    f"{self.spec.name} 协议错误: {msg['error']}")
            return msg.get("result") or {}

    def _write(self, payload: dict) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        try:
            self._proc.stdin.write(json.dumps(payload) + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError) as exc:
            self.close()
            raise MCPClientError(
                f"{self.spec.name} 写入失败（进程可能已退出）: {exc}") from exc

    # ------------------------------------------------------------------
    # http 传输（streamable-http）
    def _post(self, payload: dict) -> tuple[str, str]:
        reason = validate_http_url(self.spec.url)     # 协议/主机名边界校验
        if reason:
            raise MCPClientError(f"{self.spec.name} 不可用: {reason}")
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(self.spec.url, data=body, headers=headers)
        opener = urllib.request.build_opener(_NoRedirect)   # 不跟随重定向
        try:
            with opener.open(req, timeout=self.spec.timeout) as resp:
                return (resp.read().decode("utf-8", errors="replace"),
                        resp.headers.get("Mcp-Session-Id", "") or "")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
            raise MCPClientError(
                f"{self.spec.name} HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise MCPClientError(
                f"{self.spec.name} 不可达（{self.spec.url}）: {exc.reason}") from exc

    # ------------------------------------------------------------------
    def _rpc(self, method: str, params: dict) -> dict:
        self._next_id += 1
        msg_id = self._next_id
        payload = {"jsonrpc": "2.0", "id": msg_id, "method": method,
                   "params": params}
        if self.spec.transport == "stdio":
            if self._proc is None:
                raise MCPClientError(f"{self.spec.name} 未连接")
            self._write(payload)
            return self._read_response(msg_id)

        raw, session = self._post(payload)
        if session:
            self._session_id = session
        msg = _parse_payload(raw)
        if msg.get("id") != msg_id:
            raise MCPClientError(f"{self.spec.name} 响应 id 不匹配: {msg}")
        if "error" in msg:
            raise MCPClientError(f"{self.spec.name} 协议错误: {msg['error']}")
        return msg.get("result") or {}

    def _notify(self, method: str, params: dict) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        if self.spec.transport == "stdio":
            if self._proc is not None:
                self._write(payload)
            return
        try:
            self._post(payload)
        except MCPClientError:
            pass          # 通知失败不致命（部分实现不接收 initialized）


def probe_server(spec: MCPServerSpec) -> tuple[list[dict], str]:
    """探测一个外部 MCP Server：返回 (工具列表, 不可用原因)。

    不可用时工具列表为空、原因非空——注册中心据此"不注册"。
    """
    reason = spec.availability()
    if reason:
        return [], reason
    try:
        with MCPClient(spec) as client:
            return client.list_tools(), ""
    except MCPClientError as exc:
        return [], str(exc)
    except Exception as exc:                        # noqa: BLE001
        return [], f"探测异常: {exc}"
