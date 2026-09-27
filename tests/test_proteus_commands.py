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
PLUGIN = (ROOT / "dsh" / ".agent-presets" / "_shared"
          / "proteus-commands.mjs")
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
      scopeShow: await get('proteus-scope').handler({ rawInput: '' }),
      scopeAdd: await get('proteus-scope').handler(
        { rawInput: 'add example.com,10.0.0.5' }),
      scopeAddRef: await get('proteus-scope').handler(
        { rawInput: 'add-ref xz.aliyun.com' }),
      scopeShow2: await get('proteus-scope').handler({ rawInput: 'list' }),
      scopeBad: await get('proteus-scope').handler({ rawInput: 'frobnicate x' }),
      tree: await get('proteus-tree').handler({ rawInput: '' }),
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
        "import sys, os, json\n"
        "argv = sys.argv[1:]\n"
        "if argv[:1] == ['evidence']:\n"
        "    print('证据链：桩 · 校验 通过')\n"
        "elif argv[:1] == ['tree']:\n"
        "    print('任务 桩id · success · 127.0.0.1')\n"
        "    print('  ├─ #1 codec_decode [OK]')\n"
        "elif argv[:1] == ['scope']:\n"
        "    path = os.path.join('data', 'session-scope.json')\n"
        "    cur, ref = [], []\n"
        "    if os.path.exists(path):\n"
        "        blob = json.load(open(path, encoding='utf-8'))\n"
        "        cur = blob.get('targets', [])\n"
        "        ref = blob.get('reference', [])\n"
        "    def add(items, into):\n"
        "        for x in items.split(','):\n"
        "            if x and x not in into:\n"
        "                into.append(x)\n"
        "    if '--add' in argv:\n"
        "        add(argv[argv.index('--add') + 1], cur)\n"
        "    if '--add-ref' in argv:\n"
        "        add(argv[argv.index('--add-ref') + 1], ref)\n"
        "    if '--remove-ref' in argv:\n"
        "        ref = [x for x in ref if x not in argv[argv.index('--remove-ref') + 1].split(',')]\n"
        "    if '--add' in argv or '--add-ref' in argv or '--remove-ref' in argv:\n"
        "        os.makedirs('data', exist_ok=True)\n"
        "        json.dump({'targets': cur, 'reference': ref}, open(path, 'w', encoding='utf-8'))\n"
        "    print(json.dumps({'targets': cur, 'reference': ref}))\n"
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
        "proteus-mode", "proteus-evidence", "proteus-skills", "proteus-scope",
        "proteus-tree", "proteus-audit"]


def test_scope_command_is_human_authorization_entry(fake_ws):
    """P0-4：/proteus-scope 是"永久授权"的人工入口（模型不能自我授权）。"""
    result = _run_plugin(fake_ws)

    assert result["scopeShow"]["kind"] == "success"
    assert "会话授权目标" in result["scopeShow"]["text"]
    assert "模型不能自我授权" in result["scopeShow"]["text"]

    assert result["scopeAdd"]["kind"] == "success", result["scopeAdd"]
    scope_file = fake_ws / "proteus-agent" / "data" / "session-scope.json"
    assert json.loads(scope_file.read_text(encoding="utf-8"))["targets"] == \
        ["example.com", "10.0.0.5"]

    assert result["scopeBad"]["kind"] == "error"
    assert "未知子命令" in result["scopeBad"]["text"]


def test_scope_add_ref_is_read_only_reference_channel(fake_ws):
    """`/proteus-scope add-ref`（2026-09-27 实测）：公开 WP/知识库的只读通道。

    读一篇 WP 不该要求把公开站点写进目标授权（那会让攻击面工具也够到它）。
    判据：写进同一个文件的 `reference` 字段、与 `targets` 互不覆盖、list 两类都显示。
    """
    result = _run_plugin(fake_ws)

    assert result["scopeAddRef"]["kind"] == "success", result["scopeAddRef"]
    assert "只读参考站" in result["scopeAddRef"]["text"]
    assert "只对读取类工具生效" in result["scopeAddRef"]["text"]

    blob = json.loads(
        (fake_ws / "proteus-agent" / "data" / "session-scope.json")
        .read_text(encoding="utf-8"))
    assert blob["reference"] == ["xz.aliyun.com"]
    assert blob["targets"] == ["example.com", "10.0.0.5"]   # 没被覆盖

    assert "只读参考站" in result["scopeShow2"]["text"]
    assert "xz.aliyun.com" in result["scopeShow2"]["text"]


def test_tree_command_spawns_kernel_cli(fake_ws):
    """P2-3：/proteus-tree 走内核 CLI（与 `python -m penagent tree` 同一实现）。"""
    tree = _run_plugin(fake_ws)["tree"]
    assert tree["kind"] == "success", tree
    assert "任务" in tree["text"] and "codec_decode" in tree["text"]


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
    # 未配 sessionKey → default 目录（配了则按 preset 分开，见下一条）
    out_dir = fake_ws / "proteus-agent" / "data" / "dsh-skills" / "default"
    assert out_dir.is_dir()


def test_skills_export_dir_follows_session_key(fake_ws):
    """P1-5：技能导出按会话键分目录，与 skill-filesystem 的 customSkillDirs 同源。"""
    repo = fake_ws / "proteus-agent"
    runner = repo / "runner.mjs"
    runner.write_text(textwrap.dedent("""
        const { pathToFileURL } = await import('node:url')
        const mod = await import(pathToFileURL(process.env.PLUGIN_PATH).href)
        const captured = []
        mod.apply({ commands: { register: (d) => captured.push(d) } },
                  { sessionKey: 'ctf-web' })
        const cmd = captured.find((c) => c.name === 'proteus-skills')
        console.log(JSON.stringify(await cmd.handler({ rawInput: '' })))
    """), encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "PLUGIN_PATH": str(PLUGIN),
        "PENTEST_WS": str(fake_ws),
        "PENTEST_PY312": str(Path(sys.executable).parent),
        "PYTHONIOENCODING": "utf-8",
    }
    proc = subprocess.run([NODE, str(runner)], env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=60, cwd=str(repo))
    assert proc.returncode == 0, proc.stderr[:400]
    assert json.loads(proc.stdout.strip().splitlines()[-1])["kind"] == "success"
    assert (repo / "data" / "dsh-skills" / "ctf-web").is_dir()


def test_audit_command_reads_spool_and_chain(fake_ws):
    audit = _run_plugin(fake_ws)["audit"]
    assert audit["kind"] == "success", audit
    assert "2 条事件" in audit["text"]
    assert "pwsh" in audit["text"] and "pentest_run" in audit["text"]
    assert "offset" in audit["text"]
    assert "1 条记录" in audit["text"]
