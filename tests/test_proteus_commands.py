"""proteus-commands.mjs 端到端测试（F2/F3/F4/F5）。

用 node 真正加载插件模块并调用命令 handler——覆盖：注册名、模式查询/设置/
拒绝、证据命令 spawn 链路、技能导出 spawn 链路、审计快览
（假工作区 + 桩 penagent 包 + 审计桩，不打真实数据）。
"""
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "dsh" / ".agent-presets" / "proteus" / "proteus-commands.mjs"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node 不可用")

RUNNER = textwrap.dedent("""
    const { pathToFileURL } = await import('node:url')
    const mod = await import(pathToFileURL(process.env.PLUGIN_PATH).href)
    const captured = []
    mod.apply({ commands: { register: (d) => captured.push(d) } })
    const get = (name) => captured.find((c) => c.name === name)
    const out = {
      names: captured.map((c) => c.name),
      show: get('proteus-mode').handler({ rawInput: '' }),
      set: get('proteus-mode').handler({ rawInput: 'ctf-web' }),
      bad: get('proteus-mode').handler({ rawInput: 'ghost-mode' }),
      evidence: await get('proteus-evidence').handler({ rawInput: '' }),
      skills: await get('proteus-skills').handler({ rawInput: '' }),
      audit: get('proteus-audit').handler({}),
    }
    console.log(JSON.stringify(out))
""")


@pytest.fixture()
def fake_ws(tmp_path: Path) -> Path:
    """假工作区：<ws>/proteus-agent = 仓库根（modes/ + 桩 penagent 包 + 审计桩）。"""
    root = tmp_path / "ws" / "proteus-agent"
    (root / "modes").mkdir(parents=True)
    for mid in ("base", "ctf-web", "ctf-crypto", "pentest-standard"):
        (root / "modes" / f"{mid}.yaml").write_text(f"id: {mid}\n", encoding="utf-8")
    pkg = root / "penagent"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__main__.py").write_text(
        "import sys, os\n"
        "argv = sys.argv[1:]\n"
        "if argv[:1] == ['evidence']:\n"
        "    print('证据链：桩 · 校验 通过')\n"
        "elif argv[:1] == ['skills'] and '--export' in argv:\n"
        "    out = argv[argv.index('--out') + 1]\n"
        "    os.makedirs(out, exist_ok=True)\n"
        "    print(f'技能导出: 2 条 → {out}')\n"
        "    print('  - pentest-standard-stub01.md')\n"
        "else:\n"
        "    raise SystemExit(f'未知子命令: {argv}')\n",
        encoding="utf-8")
    # 审计桩：spool 2 条 + dsh-sync 状态 + 独立证据链 1 行
    data = root / "data"
    data.mkdir()
    (data / "dsh-events.jsonl").write_text(
        '{"ts":"2026-09-23T10:00:00","tool":"pwsh","ok":true,"preset":"proteus"}\n'
        '{"ts":"2026-09-23T10:01:00","tool":"mcp__proteus__pentest_run","ok":true,'
        '"preset":"proteus"}\n', encoding="utf-8")
    (data / "dsh-spool.state.json").write_text(
        json.dumps({"offset": 2, "updated_at": "2026-09-23T10:02:00"}),
        encoding="utf-8")
    (data / "dsh-chain.jsonl").write_text('{"seq":1}\n', encoding="utf-8")
    return tmp_path / "ws"


def _run_plugin(ws: Path) -> dict:
    repo = ws / "proteus-agent"
    runner = repo / "runner.mjs"
    runner.write_text(RUNNER, encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "PLUGIN_PATH": str(PLUGIN),
        "PENTEST_WS": str(ws),
        "PENTEST_PY312": str(Path(sys.executable).parent),
        # 桩 __main__.py 未做输出编码兜底（真实 cli.py main() 已做）——
        # 这里用环境变量把子进程输出钉成 utf-8，避免 GBK 环境下误报。
        "PYTHONIOENCODING": "utf-8",
    }
    proc = subprocess.run([NODE, str(runner)], env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=60, cwd=str(repo))
    assert proc.returncode == 0, f"node 执行失败: {proc.stderr[:400]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_commands_registered(fake_ws):
    assert _run_plugin(fake_ws)["names"] == [
        "proteus-mode", "proteus-evidence", "proteus-skills", "proteus-audit"]


def test_mode_flow(fake_ws):
    result = _run_plugin(fake_ws)

    assert result["show"]["kind"] == "success"
    assert "当前会话模式" in result["show"]["text"]

    assert result["set"]["kind"] == "success"
    mode_file = fake_ws / "proteus-agent" / "data" / "session-mode.json"
    assert json.loads(mode_file.read_text(encoding="utf-8"))["mode"] == "ctf-web"

    assert result["bad"]["kind"] == "error"
    assert "ghost-mode" in result["bad"]["text"]


def test_evidence_command_spawns_kernel_cli(fake_ws):
    ev = _run_plugin(fake_ws)["evidence"]
    assert ev["kind"] == "success", ev
    assert "证据链" in ev["text"]


def test_skills_command_spawns_export(fake_ws):
    sk = _run_plugin(fake_ws)["skills"]
    assert sk["kind"] == "success", sk
    assert "技能导出" in sk["text"] and "2 条" in sk["text"]
    out_dir = fake_ws / "proteus-agent" / "data" / "dsh-skills"
    assert out_dir.is_dir()


def test_audit_command_reads_spool_and_chain(fake_ws):
    audit = _run_plugin(fake_ws)["audit"]
    assert audit["kind"] == "success", audit
    assert "2 条事件" in audit["text"]
    assert "pwsh" in audit["text"] and "pentest_run" in audit["text"]
    assert "offset" in audit["text"]
    assert "1 条记录" in audit["text"]
