"""proteus-commands.mjs 端到端测试（F2/F3）。

用 node 真正加载插件模块并调用命令 handler——覆盖：注册名、模式查询/设置/
拒绝、证据命令的 spawn 链路（假工作区 + 桩 penagent 包，不打真实数据）。
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
    const mode = captured.find((c) => c.name === 'proteus-mode')
    const ev = captured.find((c) => c.name === 'proteus-evidence')
    const out = {
      names: captured.map((c) => c.name),
      show: mode.handler({ rawInput: '' }),
      set: mode.handler({ rawInput: 'ctf-web' }),
      bad: mode.handler({ rawInput: 'ghost-mode' }),
      evidence: await ev.handler({ rawInput: '' }),
    }
    console.log(JSON.stringify(out))
""")


@pytest.fixture()
def fake_ws(tmp_path: Path) -> Path:
    """假工作区：<ws>/proteus-agent = 仓库根（modes/ + 桩 penagent 包）。"""
    root = tmp_path / "ws" / "proteus-agent"
    (root / "modes").mkdir(parents=True)
    for mid in ("base", "ctf-web", "ctf-crypto", "pentest-standard"):
        (root / "modes" / f"{mid}.yaml").write_text(f"id: {mid}\n", encoding="utf-8")
    pkg = root / "penagent"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__main__.py").write_text(
        "import sys\n"
        "if sys.argv[1:2] == ['evidence']:\n"
        "    print('证据链：桩 · 校验 通过')\n"
        "else:\n"
        "    raise SystemExit(f'未知子命令: {sys.argv[1:]}')\n",
        encoding="utf-8")
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


def test_commands_registered_and_mode_flow(fake_ws):
    result = _run_plugin(fake_ws)

    assert result["names"] == ["proteus-mode", "proteus-evidence"]

    assert result["show"]["kind"] == "success"
    assert "当前会话模式" in result["show"]["text"]

    assert result["set"]["kind"] == "success"
    mode_file = fake_ws / "proteus-agent" / "data" / "session-mode.json"
    assert json.loads(mode_file.read_text(encoding="utf-8"))["mode"] == "ctf-web"

    assert result["bad"]["kind"] == "error"
    assert "ghost-mode" in result["bad"]["text"]


def test_evidence_command_spawns_kernel_cli(fake_ws):
    result = _run_plugin(fake_ws)
    ev = result["evidence"]
    assert ev["kind"] == "success", ev
    assert "证据链" in ev["text"]
