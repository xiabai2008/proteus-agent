"""PacketForge 适配层：把 AI 网络分析工具库接入 XPentest ToolRegistry。

PacketForge 提供 Nmap 扫描 / tshark 抓包分析 / 威胁情报 / 凭据提取（纯 Python 库）。
本地可能滞后远程：导入前校验包可用性，缺失时注册"不可用提示"工具。
接入前 git pull：<WS>/PacketForge
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

PACKETFORGE_ROOT = Path("<WS>/PacketForge")


def _load_packetforge():
    """动态导入 packetforge 包（返回 None 表示不可用）。"""
    if not PACKETFORGE_ROOT.exists():
        return None
    if str(PACKETFORGE_ROOT) not in sys.path:
        sys.path.insert(0, str(PACKETFORGE_ROOT))
    try:
        from packetforge.interfaces.nmap_interface import NmapInterface

        return {"nmap": NmapInterface}
    except Exception:
        return None


def register_packetforge(registry) -> dict:
    """注册 PacketForge 工具。包不可用时**不注册**（LLM 看不到）。"""
    from penagent.tools import ToolSpec

    pf = _load_packetforge()
    if pf is None:
        return {"loaded": 0, "tools": [],
                "note": "PacketForge 不可用（本地缺失或损坏），"
                        "请 git pull <WS>/PacketForge 后重试"}
    nmap = pf["nmap"]()

    def _nmap_scan(target: str, ports: str = "1-1000",
                   scan_type: str = "tcp") -> dict:
        try:
            out = nmap.port_scan(target, ports, scan_type)
            return {"target": target, "ports": ports, "output": out[-2000:]}
        except Exception as exc:
            return {"error": str(exc)}

    def _nmap_services(target: str, ports: str = "80,443,8080") -> dict:
        try:
            out = nmap.service_detection(target, ports)
            return {"target": target, "output": out[-2000:]}
        except Exception as exc:
            return {"error": str(exc)}

    def _nmap_vuln(target: str, ports: str = "80,443,8080") -> dict:
        try:
            out = nmap.vulnerability_scan(target, ports)
            return {"target": target, "output": out[-2000:]}
        except Exception as exc:
            return {"error": str(exc)}

    specs = [
        ToolSpec(name="pf_nmap_scan",
                 description="PacketForge Nmap 端口扫描（tcp/udp/syn）",
                 parameters={"target": {"type": "string"},
                             "ports": {"type": "string"},
                             "scan_type": {"type": "string"}},
                 fn=_nmap_scan, dangerous=True),
        ToolSpec(name="pf_nmap_services",
                 description="PacketForge Nmap 服务版本探测",
                 parameters={"target": {"type": "string"},
                             "ports": {"type": "string"}},
                 fn=_nmap_services, dangerous=True),
        ToolSpec(name="pf_nmap_vuln",
                 description="PacketForge Nmap 漏洞扫描（NSE 脚本）",
                 parameters={"target": {"type": "string"},
                             "ports": {"type": "string"}},
                 fn=_nmap_vuln, dangerous=True),
    ]
    for s in specs:
        registry.register(s)
    return {"loaded": len(specs), "tools": [s.name for s in specs],
            "note": "PacketForge 已加载"}
