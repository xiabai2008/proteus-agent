"""RayScan 适配层：wvs 库（WAVScanner）接入 XPentest ToolRegistry。

RayScan v2.1.0 的 quick/full_scan 脚本目标硬编码，这里直接用其 wvs 库
编程 API：WAVScanner().scan(ScanTarget(url=...)) 扫描指定 URL。
本地可能滞后远程：导入前校验，不可用不注册。
"""
from __future__ import annotations

import sys
from pathlib import Path

RAYSCAN_ROOT = Path("<WS>/RayScan")


def _load_rayscan():
    """动态导入 wvs 包（返回 WAVScanner 类或 None）。"""
    if not RAYSCAN_ROOT.exists():
        return None
    if str(RAYSCAN_ROOT) not in sys.path:
        sys.path.insert(0, str(RAYSCAN_ROOT))
    try:
        from wvs.core.scanner import WAVScanner

        return WAVScanner
    except Exception:
        return None


def register_rayscan(registry) -> dict:
    """注册 RayScan 工具（wvs 库）。不可用不注册。"""
    from penagent.tools import ToolSpec

    wav = _load_rayscan()
    if wav is None:
        return {"loaded": 0, "tools": [],
                "note": "RayScan wvs 库不可用（本地缺失或损坏），"
                        "请 git pull <WS>/RayScan 后重试"}

    def _scan(url: str, timeout: int = 600) -> dict:
        try:
            from wvs.models import ScanTarget

            import asyncio

            async def run():
                scanner = wav()
                return await scanner.scan(ScanTarget(url=url))

            result = asyncio.run(run())
            vulns = [
                {"type": v.vulnerability_type.value
                 if hasattr(v.vulnerability_type, "value") else str(
                     v.vulnerability_type),
                 "severity": v.severity.value
                 if hasattr(v.severity, "value") else str(v.severity),
                 "url": v.url, "confidence": v.confidence.value
                 if hasattr(v.confidence, "value") else str(v.confidence)}
                for v in getattr(result, "vulnerabilities", [])
            ]
            return {
                "target": url, "vulnerabilities": vulns,
                "vuln_count": len(vulns),
                "requests_made": getattr(result, "requests_made", 0),
                "endpoints_found": getattr(result, "endpoints_found", 0),
                "duration_s": round(getattr(result, "duration", 0), 2),
            }
        except Exception as exc:
            return {"error": f"RayScan 扫描失败: {exc}"}

    spec = ToolSpec(
        name="rayscan_scan",
        description="RayScan wvs 全栈扫描（WAVScanner：SQLi/XSS/OA，"
                    "多引擎聚合）",
        parameters={"url": {"type": "string"}},
        fn=_scan, dangerous=True, timeout=900,
    )
    registry.register(spec)
    return {"loaded": 1, "tools": ["rayscan_scan"],
            "note": "RayScan wvs 库已加载"}
