"""测试用桩 MCP Server（stdio JSON-RPC）：验证外部 MCP 工具接入链路。

不依赖任何 SDK，也不做真实网络/文件操作：
  - echo(text) -> 原样回显
  - add(a, b)  -> 两数相加（验证参数 schema 透传）
"""
import json
import sys

TOOLS = [
    {"name": "echo", "description": "回显输入文本",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string"}},
                     "required": ["text"]}},
    {"name": "add", "description": "两数相加",
     "inputSchema": {"type": "object",
                     "properties": {"a": {"type": "number"},
                                    "b": {"type": "number"}},
                     "required": ["a", "b"]}},
]


def _result(msg_id, result):
    return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg_id = msg.get("id")
        if msg_id is None:            # 通知：不回应
            continue
        method = msg.get("method", "")
        if method == "initialize":
            out = _result(msg_id, {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "stub", "version": "0.0.1"}})
        elif method == "tools/list":
            out = _result(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name", "")
            args = params.get("arguments") or {}
            if name == "echo":
                text = str(args.get("text", ""))
            elif name == "add":
                text = str(args.get("a", 0) + args.get("b", 0))
            else:
                out = _result(msg_id, {
                    "isError": True,
                    "content": [{"type": "text", "text": f"未知工具 {name}"}]})
                print(out, flush=True)
                continue
            out = _result(msg_id, {"content": [{"type": "text", "text": text}]})
        else:
            out = json.dumps({"jsonrpc": "2.0", "id": msg_id,
                              "error": {"code": -32601,
                                        "message": f"不支持: {method}"}})
        print(out, flush=True)


if __name__ == "__main__":
    main()
