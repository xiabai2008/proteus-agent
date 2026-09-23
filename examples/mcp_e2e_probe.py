"""MCP 联调探针：通过内核 discover_mcp 真实连接外部 MCP server。

用法：
  python examples/mcp_e2e_probe.py rayscan          # HTTP: list_modules
  python examples/mcp_e2e_probe.py chameleon        # stdio: scrape 公网只读靶标

只做只读/低危调用，目标限定 127.0.0.1（靶子由 examples/target.py 提供）。
命令行参数只用于从固定探针表里**选择**要跑哪个探针——参数值本身不参与
任何工具调用构造（防注入：污点在分发处即被字面量断开）。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from penagent.registry import build_center  # noqa: E402


def _probe(name: str, mode_id: str, call) -> int:
    """共用链路：discover -> 建注册表 -> 执行一次固定调用。

    name / mode_id 只来自探针表里的字面量（见下方 PROBES），call 是固定闭包：
    命令行参数只负责"选探针"，不流入任何调用构造。
    """
    from penagent.modes import load_mode
    center = build_center()
    report = center.discover_mcp(name)
    print(f"[{name}] discover 报告: {json.dumps(report, ensure_ascii=False)}")
    # rayscan 在 mcp_servers.json 里声明 modes=["pentest-standard"]，
    # 需以该模式构建注册表才会可见；chameleon 未限定模式。
    mode = load_mode(mode_id) if mode_id else None
    reg = center.build_registry(mode=mode, kernel_only=False)
    tools = [n for n in reg.names() if n.startswith(f"{name}_")]
    print(f"[{name}] 注册工具 {len(tools)} 个: {tools}")
    if not tools:
        return 1
    out = call(reg)
    d = out.to_dict() if hasattr(out, "to_dict") else vars(out)
    print(f"[{name}] 调用 ok={d.get('ok')} 输出片段: "
          f"{str(d.get('output') or d.get('error'))[:260]}")
    return 0 if d.get("ok") else 1


def probe_rayscan() -> int:
    return _probe("rayscan", "pentest-standard",
                  lambda reg: reg.execute("rayscan_list_modules", {}))


def probe_chameleon() -> int:
    # Chameleon 自带 SSRF 防护，会拒绝 127.0.0.1 等内网地址（其组件安全策略，
    # 属预期行为）；改用公网只读地址验证完整采集链路。
    return _probe("chameleon", "",
                  lambda reg: reg.execute("chameleon_scrape_url",
                                          {"url": "https://example.com/"}))


def probe_seckb() -> int:
    return _probe("seckb", "",
                  lambda reg: reg.execute("seckb_kb_search",
                                          {"query": "langflow CVE-2025-3248"}))


def probe_radare2() -> int:
    # ⚠️ 未接线（2026-09-23）：r2mcp v1.8.8 的 tools/list 死锁——握手 init 正常
    # （4s）、ping 正常，但 tools/list 90s 无任何响应且进程存活、无崩溃输出，
    # 疑似上游缺陷。故 mcp_servers.json 暂未挂 radare2 条目（挂了会让发现流程
    # 每次等 120s 超时）。本分支保留，修好后接线即可用。
    # 跟进选项：① 给上游提 issue / 找已修版本；② 用 r2mcp -T 的 CLI 能力自制
    # 薄 MCP 包装；③ 改试 GhidraMCP 路线。分析对象用发行版自带 /bin/ls。
    return _probe("radare2", "",
                  lambda reg: reg.execute("radare2_open_file",
                                          {"file_path": "/bin/ls"}))


# 容器化 MCP（mcp-security-hub 本地构建；data 目录只读挂到容器 /samples）。
# 分析样本用 ghostpatch 里割出的 fw_v2.bin（真实 ELF，扫描无副作用）。
def probe_binwalk() -> int:
    return _probe("binwalk", "",
                  lambda reg: reg.execute("binwalk_binwalk_scan",
                                          {"filepath":
                                           "/samples/ctf/ghostpatch/fw_v2.bin"}))


def probe_searchsploit() -> int:
    return _probe("searchsploit", "",
                  lambda reg: reg.execute("searchsploit_searchsploit_search",
                                          {"query": "apache 2.4"}))


def probe_capa() -> int:
    return _probe("capa", "",
                  lambda reg: reg.execute("capa_capa_analyze",
                                          {"filepath":
                                           "/samples/ctf/ghostpatch/fw_v2.bin"}))


def probe_cyberchef() -> int:
    # 依赖：proteus-cyberchef-server 容器在宿主 127.0.0.1:3110 运行（见 README）。
    return _probe("cyberchef", "",
                  lambda reg: reg.execute("cyberchef_bake_recipe",
                                          {"input_data": "hello",
                                           "recipe": [{"op": "To Base64"}]}))


PROBES = {"rayscan": probe_rayscan,
          "chameleon": probe_chameleon,
          "seckb": probe_seckb,
          "radare2": probe_radare2,
          "binwalk": probe_binwalk,
          "searchsploit": probe_searchsploit,
          "capa": probe_capa,
          "cyberchef": probe_cyberchef}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in PROBES:
        print(__doc__)
        sys.exit(2)
    sys.exit(PROBES[sys.argv[1]]())
