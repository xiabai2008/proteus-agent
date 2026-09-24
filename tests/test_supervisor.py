"""proteus-supervisor.mjs 行为测试（P2-1：宿主侧循环检测与救场）。

真实背景：2026-09-22 实测一次会话 20 步里有 13 步在重复同一个
`http_raw /ftp`（长页面把文件清单挤到截断线之后，模型就一遍遍加大
max_body）。这类循环烧掉整轮预算，而内核看不见（那是外层 agent 的行为）。

用例覆盖：阈值内放行 / 同参数重复到阈值被拦 / 不同参数不误伤 /
第二次触发升级为 ask / 留痕进 spool / 会话隔离。
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
          / "proteus-supervisor.mjs")
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node 不可用")

RUNNER = textwrap.dedent("""
    const { pathToFileURL } = await import('node:url')
    const mod = await import(pathToFileURL(process.env.PLUGIN_PATH).href)

    const listeners = []
    mod.apply({ on: (name, fn) => listeners.push(fn) }, {
      spoolPath: process.env.SPOOL,
      sameToolLimit: 3,
      totalLimit: 100,
      escalate: 'ask',
    })
    const pre = listeners[0]
    const next = async () => ({ kind: 'next' })
    const agent = { session: { header: { id: 's1' } } }
    const agent2 = { session: { header: { id: 's2' } } }
    const call = async (tool, args, who) =>
      await pre({ name: tool, arguments: args, agent: who || agent }, next)

    const out = { steps: [] }
    // 同一工具同参数连调 4 次（阈值 3）：前两次放行，第三次起被拦
    for (let i = 0; i < 4; i++) {
      out.steps.push(await call('pwsh', { command: 'curl http://127.0.0.1/' }))
    }
    // 换个参数不该被拦
    out.otherArgs = await call('pwsh', { command: 'curl http://127.0.0.1/x' })
    // 另一个会话独立计数
    out.otherSession = await call('pwsh',
      { command: 'curl http://127.0.0.1/' }, agent2)
    // 再触发一次：升级为 ask
    out.escalated = await call('pwsh', { command: 'curl http://127.0.0.1/' })
    console.log(JSON.stringify(out))
""")


@pytest.fixture()
def ws(tmp_path: Path) -> Path:
    return tmp_path


def _run(ws: Path) -> dict:
    runner = ws / "runner.mjs"
    runner.write_text(RUNNER, encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SystemRoot": os.environ.get("SystemRoot", ""),
        "PLUGIN_PATH": str(PLUGIN),
        "SPOOL": str(ws / "data" / "dsh-events.jsonl"),
    }
    proc = subprocess.run([NODE, str(runner)], env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=60, cwd=str(ws))
    assert proc.returncode == 0, f"node 执行失败: {proc.stderr[:400]}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_repeat_loop_is_denied_with_advice(ws):
    r = _run(ws)
    kinds = [s.get("kind") for s in r["steps"]]
    assert kinds[:2] == ["next", "next"]          # 阈值内不打扰
    assert kinds[2] == "deny"                     # 第一次介入：拒绝 + 提示
    assert kinds[3] == "ask"                      # 第二次介入：升级为审批
    reason = r["steps"][2]["reason"]
    assert "重复 3 次" in reason
    assert "换思路" in reason and "grep" in reason   # 理由要可操作


def test_different_args_are_not_punished(ws):
    assert _run(ws)["otherArgs"] == {"kind": "next"}


def test_sessions_count_independently(ws):
    assert _run(ws)["otherSession"] == {"kind": "next"}


def test_second_intervention_escalates_to_ask(ws):
    """第一次 deny 之后仍重复 → 升级为 ask（让人看一眼，而不是无限拒绝）。"""
    assert _run(ws)["escalated"]["kind"] == "ask"


def test_interventions_leave_audit_records(ws):
    _run(ws)
    lines = (ws / "data" / "dsh-events.jsonl").read_text(
        encoding="utf-8").strip().splitlines()
    records = [json.loads(x) for x in lines]
    assert records and all(r["kind"] == "supervisor" for r in records)
    assert {r["decision"] for r in records} == {"deny", "ask"}
    assert records[0]["tool"] == "pwsh" and records[0]["session"] == "s1"
