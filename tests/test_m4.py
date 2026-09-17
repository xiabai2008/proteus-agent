"""M4 测试：RayScan adapter / 技能盲区发现。"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.gaps import analyze_gaps
from penagent.memory import Memory


# ----------------------------------------------------------------------
def test_gaps_tool_stats(tmp_path):
    m = Memory(tmp_path)
    mid = m.new_mission("http://x", "侦察")
    m.add_step(mid, {"step": 1, "tool": "dns_lookup", "ok": False})
    m.add_step(mid, {"step": 2, "tool": "dns_lookup", "ok": False})
    m.add_step(mid, {"step": 3, "tool": "port_scan", "ok": True})
    m.add_step(mid, {"step": 4, "tool": "poxiao_scan", "blocked": True})
    m.finish(mid, "failed")
    r = analyze_gaps(m)
    assert r["missions"] == 1
    assert r["tool_usage"]["dns_lookup"]["fail"] == 2
    assert r["tool_usage"]["port_scan"]["ok"] == 1
    assert r["tool_usage"]["poxiao_scan"]["blocked"] == 1
    # 规则建议
    assert any("dns_lookup" in s and "失败率" in s
               for s in r["suggestions"])
    assert any("poxiao_scan" in s and "拦截" in s
               for s in r["suggestions"])


def test_gaps_no_missions(tmp_path):
    r = analyze_gaps(Memory(tmp_path))
    assert r["missions"] == 0
    assert r["tool_usage"] == {}
    assert r["suggestions"] == []


def test_gaps_llm_mode_no_data(tmp_path):
    from penagent.gaps import analyze_gaps_llm

    r = analyze_gaps_llm(Memory(tmp_path))
    assert r["missions"] == 0
    assert "尚无作战数据" in r["recommendations"][0]


def test_rayscan_adapter_registration():
    """RayScan wvs 库可用时注册，否则返回不可用提示且不注册。"""
    from penagent.adapters.rayscan import register_rayscan
    from penagent.tools import ToolRegistry

    reg = ToolRegistry()
    info = register_rayscan(reg)
    if info["loaded"]:
        assert "rayscan_scan" in reg.names()
        spec = reg.get("rayscan_scan")
        assert spec.dangerous is True
        assert "url" in spec.parameters
    else:
        assert "rayscan_scan" not in reg.names()
        assert "不可用" in info["note"]
