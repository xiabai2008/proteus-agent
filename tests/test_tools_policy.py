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
PLUGIN = (ROOT / "dsh" / ".agent-presets" / "_shared"
          / "proteus-tools-policy.mjs")
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
        modePath: process.env.MODE,
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

# P0-5：模式驱动的档位——用同一个 runner 再跑一遍（会话模式 = ctf-web），
# 以及"CTF 模式 + 越界目标"（越界不走放行表）
MODE_RUNNER = textwrap.dedent("""
    const { pathToFileURL } = await import('node:url')
    const mod = await import(pathToFileURL(process.env.PLUGIN_PATH).href)
    const listeners = {}
    mod.apply({
      on: (name, fn) => { (listeners[name] ||= []).push(fn) },
      tools: { schemas: () => [{ name: 'mcp__proteus__http_raw' }] },
    }, {
      role: 'policy', mode: 'ask', kernelGuard: 'deny',
      targets: ['127.0.0.1', 'localhost'], shellTools: ['pwsh'],
      spoolPath: process.env.SPOOL, scopePath: process.env.SCOPE,
      modePath: process.env.MODE,
    })
    const pre = listeners['tools/pre-execute'][0]
    const next = async () => ({ kind: 'next' })
    const run = async (command) =>
      await pre({ name: 'pwsh', arguments: { command }, agent: null }, next)
    console.log(JSON.stringify({
      inScope: await run('curl http://127.0.0.1:3000/'),
      outScope: await run('curl http://evil.example.com/'),
    }))
""")


@pytest.fixture()
def ws(tmp_path: Path) -> Path:
    """假工作区：spool + 会话授权文件（含一个已授权目标）。"""
    data = tmp_path / "data"
    data.mkdir()
    (data / "session-scope.json").write_text(
        json.dumps({"targets": ["allowed.example.com"]}), encoding="utf-8")
    return tmp_path


# 审计路径：preset 归属打标（2026-09-27 实测缺陷——会话头是"创建时"的值，
# 用户在会话里切 preset 后不更新，于是 proteus 会话被记成 standard）。
AUDIT_RUNNER = textwrap.dedent("""
    const { pathToFileURL } = await import('node:url')
    const mod = await import(pathToFileURL(process.env.PLUGIN_PATH).href)
    const listeners = {}
    const ctx = { on: (name, fn) => { (listeners[name] ||= []).push(fn) } }
    mod.apply(ctx, { role: 'audit', spoolPath: process.env.SPOOL })
    const emit = listeners['session/event'][0]

    const toolCall = (time, name) => ({
      type: 'tool/call', time,
      data: { name, arguments: {}, turn: 1, step: 1, callId: `c${time}` },
    })
    const selected = (time, preset) => ({
      type: 'agent-preset/selected', time, data: { agentPreset: preset },
    })

    // A：会话头 standard，随后切到 proteus-ctf-crypto（实测形状）
    const a = { header: { id: 'session-a', agentPreset: 'standard' } }
    emit(a, toolCall(1, 'read'))                       // 选择之前：仍是旧值
    emit(a, selected(2, 'proteus-ctf-crypto'))
    emit(a, toolCall(3, 'native_emu'))                 // 选择之后：应标新值

    // B：没有选择事件 → 回退会话头
    const b = { header: { id: 'session-b', agentPreset: 'proteus-ctf-web' } }
    emit(b, toolCall(4, 'http_raw'))

    // C：选择事件的值为空 → 不覆盖成空串，保持会话头
    const c = { header: { id: 'session-c', agentPreset: 'standard' } }
    emit(c, selected(5, ''))
    emit(c, toolCall(6, 'read'))

    // D：其它事件类型不留痕
    const d = { header: { id: 'session-d', agentPreset: 'standard' } }
    emit(d, { type: 'step/start', time: 7, data: {} })

    console.log(JSON.stringify({ ok: true }))
""")


def test_audit_labels_preset_from_selection_not_stale_header(ws):
    """归属按"实际选中的 preset"打标：会话头过期时不采信它。

    2026-09-27 实测：一次 `proteus-ctf-crypto` 会话（用户先开 standard 再切 preset）
    被记成 `standard`，而 `benchmark.py --suite dsh-session --preset` 按这个字段分臂
    ——战绩会被漏掉或归错臂。判据：选择事件之后的事件带新值；选择之前的不回溯
    （spool 追加写）；没有选择事件时回退会话头；空值不覆盖已有值。
    """
    _run(ws, AUDIT_RUNNER)
    records = [json.loads(line) for line in
               (ws / "data" / "dsh-events.jsonl").read_text(
                   encoding="utf-8").strip().splitlines()]
    calls = [r for r in records if r.get("kind") == "call"]
    pairs = {(r["session"], r["tool"]): r["preset"] for r in calls}

    assert pairs[("session-a", "read")] == "standard"          # 选择之前不回溯
    assert pairs[("session-a", "native_emu")] == "proteus-ctf-crypto"
    assert pairs[("session-b", "http_raw")] == "proteus-ctf-web"  # 回退会话头
    assert pairs[("session-c", "read")] == "standard"          # 空值不覆盖
    assert len(calls) == 4                                     # step/start 不留痕


def _run(ws: Path, script: str = RUNNER, mode: str = "") -> dict:
    runner = ws / "runner.mjs"
    runner.write_text(script, encoding="utf-8")
    mode_file = ws / "data" / "session-mode.json"
    if mode:
        mode_file.write_text(json.dumps({"mode": mode}), encoding="utf-8")
    elif mode_file.exists():
        mode_file.unlink()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "PLUGIN_PATH": str(PLUGIN),
        "SPOOL": str(ws / "data" / "dsh-events.jsonl"),
        "SCOPE": str(ws / "data" / "session-scope.json"),
        "MODE": str(mode_file),
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


def test_ctf_mode_allows_in_scope_target_actions(ws):
    """P0-5：会话模式 = ctf-web 时，范围内目标动作放行（仍然留痕）。"""
    r = _run(ws, MODE_RUNNER, mode="ctf-web")
    assert r["inScope"] == {"kind": "next"}

    records = [json.loads(line) for line in
               (ws / "data" / "dsh-events.jsonl").read_text(
                   encoding="utf-8").strip().splitlines()]
    allowed = [x for x in records if x.get("decision") == "allow"]
    assert allowed and "ctf-web" in allowed[0]["reason"]


def test_ctf_mode_allows_out_of_scope_too(ws):
    """CTF 模式：越界目标也按模式档位走（不再单独抬 ask）——2026-09-27 拍板。

    内核侧同一模式已声明 `scope.unrestricted`（靶由平台给定，逐题授权是纯摩擦），
    宿主侧再弹一次"请授权"就是双重摩擦。判据：CTF 模式下越界 → `next`（放行），
    但**仍然留痕**（审计要能回答"放过了什么"）。
    """
    r = _run(ws, MODE_RUNNER, mode="ctf-web")
    assert r["outScope"]["kind"] == "next"

    records = [json.loads(line) for line in
               (ws / "data" / "dsh-events.jsonl").read_text(
                   encoding="utf-8").strip().splitlines()]
    allowed = [x for x in records if x.get("decision") == "allow"]
    assert allowed and "/proteus-scope" not in allowed[0].get("reason", "")


def test_pentest_mode_keeps_out_of_scope_ask(ws):
    """渗透系不受该放行影响：越界目标仍然至少 ask（旧口径原样保留）。"""
    r = _run(ws, MODE_RUNNER, mode="pentest-standard")
    assert r["inScope"]["kind"] == "ask"
    assert r["outScope"]["kind"] == "ask"
    assert "/proteus-scope" in r["outScope"]["reason"]


def test_unknown_mode_falls_back_to_static_tier(ws):
    """未知/未设置的会话模式 → 沿用静态 mode（ask），不放行。"""
    r = _run(ws, MODE_RUNNER, mode="")
    assert r["inScope"]["kind"] == "ask"
