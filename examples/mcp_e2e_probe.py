"""MCP 联调探针：通过内核 discover_mcp 真实连接外部 MCP server。

用法：
  python examples/mcp_e2e_probe.py rayscan          # HTTP: list_modules
  python examples/mcp_e2e_probe.py chameleon        # stdio: scrape 本地授权靶标

只做只读/低危调用，目标限定 127.0.0.1（靶子由 examples/target.py 提供）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from penagent.registry import build_center  # noqa: E402


def probe(name: str) -> int:
    from penagent.modes import load_mode
    center = build_center()
    report = center.discover_mcp(name)
    print(f"[{name}] discover 报告: {json.dumps(report, ensure_ascii=False)}")
    # rayscan 在 mcp_servers.json 里声明 modes=["pentest-standard"]，
    # 需以该模式构建注册表才会可见；chameleon 未限定模式。
    mode = load_mode("pentest-standard") if name == "rayscan" else None
    reg = center.build_registry(mode=mode, kernel_only=False)
    tools = [n for n in reg.names() if n.startswith(f"{name}_")]
    print(f"[{name}] 注册工具 {len(tools)} 个: {tools}")
    if not tools:
        return 1

    if name == "rayscan":
        out = reg.execute("rayscan_list_modules", {})
    else:
        # Chameleon 自带 SSRF 防护，会拒绝 127.0.0.1 等内网地址（其组件安全策略，
        # 属预期行为）；改用公网只读地址验证完整采集链路。
        out = reg.execute("chameleon_scrape_url",
                          {"url": "https://example.com/"})
    d = out.to_dict() if hasattr(out, "to_dict") else vars(out)
    print(f"[{name}] 调用 ok={d.get('ok')} 输出片段: "
          f"{str(d.get('output') or d.get('error'))[:260]}")
    return 0 if d.get("ok") else 1


if __name__ == "__main__":
    import json
    if len(sys.argv) != 2 or sys.argv[1] not in ("rayscan", "chameleon"):
        print(__doc__)
        sys.exit(2)
    sys.exit(probe(sys.argv[1]))
