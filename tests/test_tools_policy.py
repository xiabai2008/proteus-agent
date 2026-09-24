"""proteus-tools-policy.mjs 行为测试（preset 作用域的目标动作裁决）。

用 node 真正加载插件模块、捕获 `tools/pre-execute` 监听器并直接调用——覆盖
P0-4 起的两条新语义与既有的三条旧语义：

- 本地命令放行（不惩罚本地动作）
- 白名单内目标 → ask（理由：建议走内核）
- 白名单外目标 → ask，理由带 /proteus-scope 授权指引
- **会话授权文件里的目标视为白名单内**（与内核读同一份来源）
- **改写授权文件本身 → deny**（模型不能自我授权）
- 内核缺位 + kernelGuard=deny → deny（fail-closed）

不启动 DSH：插件只依赖 `ctx.on` 与 `ctx.tools.schemas`，桩即可。
"""
import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "dsh" / ".agent-presets" / "proteus" / "proteus-tools-policy.mjs"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node 不可用")

RUNNER = textwrap.dedent("""
    const { pathToFileURL } = await import('node:url')
    const mod = await import(pathToFileURL(process.env.PLUGIN_PATH).href)

    function mount(kernelPresent) {
      const listeners = {}
      const ctx = {
        on: (name, fn) => { (listeners[name] ||= []).push(fn) },
        tools: { schemas: () => (kernelPresent
          ? [{ name: 'mcp__proteus__http_raw' }] : [{ name: 'read' }]) },
      }
      mod.apply(ctx, {
        role: 'policy',
        mode: 'ask',
        kernelGuard: 'deny',
        targets: ['127.0.0.1', 'localhost'],
        shellTools: ['pwsh', 'bash'],
        spoolPath: process.env.SPOOL,
        scopePath: process.env.SCOPE,
      })
      return listeners['tools/pre-execute'][0]
    }

    const next = async () => ({ kind: 'next' })
    const run = async (pre, command) =>
      await pre({ name: 'pwsh', arguments: { command }, agent: null }, next)

    const withKernel = mount(true)
    const withoutKernel = mount(false)
    const out = {
      local: await run(withKernel, 'echo hello'),
      inScope: await run(withKernel, 'curl http://127.0.0.1:3000/'),
      outScope: await run(withKernel, 'curl http://evil.example.com/'),
      scoped: await run(withKernel, 'curl http://allowed.example.com/x'),
      scopedSub: await run(withKernel, 'curl http://a.allowed.example.com/'),
      tamper: await run(withKernel,
        'Set-Content -Path data/session-scope.json -Value "{}"'),
      missingKernel: await run(withoutKernel, 'curl http://127.0.0.1:3000/'),
    }
    console.log(JSON.stringify(out))
""")


@pytest.fixture()
def ws(tmp_path: Path) -> Path:
    """假工作区：spool + 会话授权文件（含一个已授权目标）。"""
    data = tmp_path / "data"
    data.mkdir()
    (data / "session-scope.json").write_text(
        json.dumps({"targets": ["allowed.example.com"]}), encoding="utf-8")
    return tmp_path


def _run(ws: Path) -> dict:
    runner = ws / "runner.mjs"
    runner.write_text(RUNNER, encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "PLUGIN_PATH": str(PLUGIN),
        "SPOOL": str(ws / "data" / "dsh-events.jsonl"),
        "SCOPE": str(ws / "data" / "session-scope.json"),
    }
    proc = subprocess.run([NODE, str(runner)], env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=60, cwd=str(ws))
    assert proc.returncode == 0, f"node 执行失败: {proc.stderr[:400]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_local_command_passes_through(ws):
    """裁决不惩罚本地动作（否则退化成"什么都要批"的噪音门）。"""
    assert _run(ws)["local"] == {"kind": "next"}


def test_target_action_asks_with_kernel_hint(ws):
    r = _run(ws)
    assert r["inScope"]["kind"] == "ask"
    assert "建议走内核工具" in r["inScope"]["reason"]


def test_out_of_scope_asks_with_authorization_hint(ws):
    r = _run(ws)
    assert r["outScope"]["kind"] == "ask"
    assert "/proteus-scope" in r["outScope"]["reason"]
    assert "模型不能自我授权" in r["outScope"]["reason"]


def test_session_scope_extends_effective_allowlist(ws):
    """人工授权过的目标不再算"越界"（与内核读同一份文件）。"""
    r = _run(ws)
    assert "不在内核授权白名单" not in r["scoped"]["reason"]
    assert "不在内核授权白名单" not in r["scopedSub"]["reason"]
    assert "不在内核授权白名单" in r["outScope"]["reason"]


def test_rewriting_scope_file_is_denied(ws):
    """自我授权防线：宿主 shell 不得改写授权文件。"""
    r = _run(ws)
    assert r["tamper"]["kind"] == "deny"
    assert "模型不能自我授权" in r["tamper"]["reason"]


def test_kernel_missing_fails_closed(ws):
    r = _run(ws)
    assert r["missingKernel"]["kind"] == "deny"
    assert "内核工具未挂载" in r["missingKernel"]["reason"]


def test_policy_records_land_in_spool(ws):
    """裁决留痕（含 deny 与 ask）——审计链要能回答"当时内核在不在"。"""
    _run(ws)
    lines = (ws / "data" / "dsh-events.jsonl").read_text(
        encoding="utf-8").strip().splitlines()
    records = [json.loads(line) for line in lines]
    kinds = {r["kind"] for r in records}
    assert "policy" in kinds
    assert any(r.get("decision") == "deny" for r in records)
