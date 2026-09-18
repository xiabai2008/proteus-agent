"""M3 测试：技能成功率回写 / positional CLI / 进化评测。"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.memory import Memory, Skill
from penagent.tools import ToolRegistry, ToolSpec


def test_skill_success_rate_roundtrip(tmp_path):
    m = Memory(tmp_path)
    s = Skill(id="s1", title="侦察", target_fingerprint="web")
    m.add_skill(s)
    loaded = m.find_skills("web service")[0]
    loaded.record_outcome(True)
    loaded.record_outcome(True)
    loaded.record_outcome(False)
    m.update_skill(loaded)
    reloaded = m.list_skills()[0]
    assert reloaded.attempts == 3
    assert reloaded.successes == 2
    assert reloaded.success_rate == pytest.approx(2 / 3)


def test_skills_sorted_by_rate(tmp_path):
    m = Memory(tmp_path)
    m.add_skill(Skill(id="a", title="低", target_fingerprint="x",
                      successes=1, attempts=4, success_rate=0.25))
    m.add_skill(Skill(id="b", title="高", target_fingerprint="y",
                      successes=3, attempts=3, success_rate=1.0))
    order = [s.id for s in m.list_skills(sort_by_rate=True)]
    assert order == ["b", "a"]


def test_skills_sorted_by_stealth(tmp_path):
    """对抗排序：暴露低优先（exposure 字段纳入进化排序）。"""
    m = Memory(tmp_path)
    m.add_skill(Skill(id="loud", title="明文注入", target_fingerprint="web",
                      successes=3, attempts=3, success_rate=1.0,
                      exposure=2))
    m.add_skill(Skill(id="stealth", title="注释混淆注入",
                      target_fingerprint="web", successes=3, attempts=3,
                      success_rate=1.0, exposure=0))
    m.add_skill(Skill(id="legacy", title="旧技能无暴露数据",
                      target_fingerprint="web", successes=2, attempts=2,
                      success_rate=1.0))
    order = [s.id for s in m.list_skills(sort_by_stealth=True)]
    assert order == ["stealth", "loud", "legacy"]
    # 暴露字段持久化往返
    reloaded = m.list_skills()
    by_id = {s.id: s for s in reloaded}
    assert by_id["stealth"].exposure == 0
    assert by_id["legacy"].exposure is None


def test_positional_cli_args():
    spec = ToolSpec(name="t", kind="cli", positional=True,
                    command=["bin", "{args}"])
    assert ToolRegistry._cli_args(spec, {"target": "http://x"}) \
        == ["http://x"]
    spec2 = ToolSpec(name="t", kind="cli", positional=False,
                     command=["bin", "{args}"])
    assert ToolRegistry._cli_args(spec2, {"target": "http://x"}) \
        == ["--target", "http://x"]


def test_external_tools_positional_flag(tmp_path):
    from penagent.external_tools import load_external_tools

    cfg = tmp_path / "t.json"
    cfg.write_text(json.dumps({"tools": {
        "pos_tool": {"description": "x",
                     "command": ["python", "-V", "{args}"],
                     "positional": True},
        "flag_tool": {"description": "x",                      "command": ["python", "-V", "{args}"]},
    }}), encoding="utf-8")
    reg = ToolRegistry()
    load_external_tools(reg, cfg)
    assert reg.get("pos_tool").positional is True
    assert reg.get("flag_tool").positional is False


def test_evolution_eval_script():
    """进化评测脚本可运行且技能型优于探索型。"""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "examples"
                            / "eval_evolution.py")],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    assert proc.returncode == 0, proc.stderr[-500:]
    out = proc.stdout
    assert "50%" in out            # 决策步数下降 50%
    assert "75%" in out            # 成功率回写 3/4


def test_evolution_llm_script_mock():
    """07 联动深化：mock 模式评测可运行且技能型步数更少。"""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "examples"
                            / "eval_evolution_llm.py"), "--mock"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=180)
    assert proc.returncode == 0, proc.stderr[-400:]
    assert "40%" in proc.stdout    # 技能型步数下降 40%


def test_poxiao_recon_registered():
    """v3.1.0 联动：poxiao_recon 从默认配置注册（本地 poxiao 已合并 v3.1.0）。"""
    from penagent.external_tools import load_external_tools

    reg = ToolRegistry()
    info = load_external_tools(reg)
    spec = reg.get("poxiao_recon")
    assert spec is not None
    assert spec.dangerous is False          # 被动信息收集，非攻击性
    assert spec.command[1] == "<WS>/poxiao/poxiao.py"
    assert spec.command[-1] == "--quick"    # 快速模式固定参数
    assert spec.workdir.endswith("poxiao")
    assert spec.positional is True
    assert info["loaded"] >= 2              # scan + recon 均注册


def test_skill_category_and_evidence(tmp_path):
    """漏洞方向标签过滤 + 工具证据文本持久化。"""
    m = Memory(tmp_path)
    m.add_skill(Skill(id="s1", title="SQLi 注入", target_fingerprint="web",
                      category="sqli", evidence_text="{\"payload\": \"union\"}",
                      successes=1, attempts=1, success_rate=1.0))
    m.add_skill(Skill(id="s2", title="XSS 检测", target_fingerprint="web",
                      category="xss", successes=1, attempts=1,
                      success_rate=1.0))
    assert [s.id for s in m.list_skills(category="sqli")] == ["s1"]
    assert [s.id for s in m.list_skills(category="recon")] == []
    reloaded = m.list_skills(category="sqli")[0]
    assert reloaded.evidence_text.startswith("{")
    assert reloaded.category == "sqli"


def test_workbench_tools_registered():
    """DawnForge 工作台工具矩阵接入：高价值工具从默认配置注册。"""
    from penagent.external_tools import load_external_tools

    # 工具矩阵按运行时存在性注册（AGENTS.md 硬规则 1 的约定）：二进制未部署的
    # 环境（CI / 新机器）不注册属预期行为，本用例仅在工具库就位的机器上有意义。
    if not Path("<TOOLS_DIR>/tools/httpx.exe").exists():
        pytest.skip("本机未部署 <TOOLS_DIR> 工具库，跳过工具矩阵断言")

    reg = ToolRegistry()
    load_external_tools(reg)
    for name, dangerous in [("httpx_probe", False), ("fscan_scan", True),
                            ("nuclei_scan", True), ("subfinder_enum", False),
                            ("dnsx_lookup", False), ("katana_crawl", False),
                            ("naabu_scan", True), ("dalfox_xss", True)]:
        spec = reg.get(name)
        assert spec is not None, f"{name} 未注册"
        assert spec.dangerous is dangerous, f"{name} 危险标记错误"
        assert "<TOOLS_DIR>/tools" in spec.command[0]
