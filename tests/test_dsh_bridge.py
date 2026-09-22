"""DSH 宿主桥测试：事件 spool -> 内核证据链（审计通道）。

为什么这些必须测：这条链的用途是"**旁路也留痕、痕迹可机验**"。留痕错了
（配对错、重复入链、形状与内核自有记录不一致）比不留痕更糟——结论看起来
可审计，实际对不上。所以下面把配对、幂等、形状与链校验逐条钉住。
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from penagent.dsh_bridge import import_spool                       # noqa: E402
from penagent.evidence import EvidenceChain                        # noqa: E402

PLUGIN = ROOT / "dsh" / "proteus-bridge" / "index.mjs"


def _spool(tmp_path: Path, events: list[dict]) -> Path:
    path = tmp_path / "dsh-events.jsonl"
    path.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n"
                            for e in events), encoding="utf-8")
    return path


def _call(call_id="c1", tool="pwsh", args='{"command":"curl x"}', **kw):
    base = {"ts": 1, "session": "s1", "kind": "call", "turn": 1, "step": 1,
            "callId": call_id, "tool": tool, "args": args}
    base.update(kw)
    return base


def _result(call_id="c1", output="STATUS: 200", is_error=False, **kw):
    base = {"ts": 2, "session": "s1", "kind": "result", "turn": 1, "step": 1,
            "callId": call_id, "isError": is_error, "error": "", "output": output}
    base.update(kw)
    return base


def test_pairs_call_and_result_into_one_record(tmp_path):
    """call/result 配对成一条内核形状的记录（tool/args/ok/output）。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [
        _call(args='{"url": "http://127.0.0.1:3000/"}'),
        _result(output="状态 200"),
    ])
    report = import_spool(spool, chain=chain, state_path=None)

    assert report["records"] == 1 and report["open_calls"] == 0
    rec = chain.load()[0]
    assert rec.kind == "tool_call"
    content = rec.content
    assert content["tool"] == "pwsh"
    assert content["args"] == {"url": "http://127.0.0.1:3000/"}   # JSON 已解析
    assert content["ok"] is True and content["output"] == "状态 200"
    assert content["source"] == "dsh" and content["call_id"] == "c1"


def test_unpaired_call_stays_pending_until_flush(tmp_path):
    """只有调用没有结果：默认**挂起不入链**（结果随后到达仍要能配对）。

    早期实现是"未配对也立即记账"，结果补上时同一次调用会留下两条记录
    ——看着可审计、实际对不上。现在的语义：挂起并跨导入持久化。
    """
    state = tmp_path / "state.json"
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [_call(call_id="c9")])

    report = import_spool(spool, chain=chain, state_path=state)
    assert report["records"] == 0 and report["open_calls"] == 1
    assert chain.load() == []

    # 结果补上后：配对上，入链一条（不是两条）
    with spool.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_result("c9", output="late")) + "\n")
    paired = import_spool(spool, chain=chain, state_path=state)
    assert paired["records"] == 1 and paired["open_calls"] == 0
    assert len(chain.load()) == 1

    # 显式冲刷：会话结束时把仍然挂起的调用按 ok=None 落链
    spool2 = _spool(tmp_path, [_call(call_id="c10")])
    flushed = import_spool(spool2, chain=chain, state_path=None,
                           flush_open=True)
    assert flushed["flushed"] == 1
    content = chain.load()[-1].content
    assert content["ok"] is None and "没有对应结果" in content["note"]


def test_error_result_maps_to_ok_false(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [_call(), _result(is_error=True, output="denied")])
    import_spool(spool, chain=chain, state_path=None)
    assert chain.load()[0].content["ok"] is False


def test_incremental_import_does_not_duplicate(tmp_path):
    """增量导入：状态文件记住偏移，重复运行不重复入链。"""
    state = tmp_path / "state.json"
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [_call(), _result()])

    first = import_spool(spool, chain=chain, state_path=state)
    second = import_spool(spool, chain=chain, state_path=state)
    assert first["records"] == 1 and second["records"] == 0
    assert len(chain.load()) == 1

    # 追加新事件后：只导入新增的那条
    with spool.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_call("c2", tool="http_raw")) + "\n")
        fh.write(json.dumps(_result("c2", output="200")) + "\n")
    third = import_spool(spool, chain=chain, state_path=state)
    assert third["records"] == 1
    assert [r.content["tool"] for r in chain.load()] == ["pwsh", "http_raw"]


def test_replay_reimports_from_scratch(tmp_path):
    state = tmp_path / "state.json"
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [_call(), _result()])
    import_spool(spool, chain=chain, state_path=state)
    again = import_spool(spool, chain=chain, state_path=state, replay=True)
    assert again["records"] == 1 and len(chain.load()) == 2


def test_partial_last_line_is_left_for_next_run(tmp_path):
    """最后一行正在被写入（无换行）时不能消费——否则会丢事件。"""
    state = tmp_path / "state.json"
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = tmp_path / "dsh-events.jsonl"
    full_result = json.dumps(_result())
    # 模拟"写了一半"：result 只是前缀，没有换行
    spool.write_text(json.dumps(_call()) + "\n" + full_result[:20],
                     encoding="utf-8")
    first = import_spool(spool, chain=chain, state_path=state)
    assert first["records"] == 0            # 残行的 result 还没到
    assert first["open_calls"] == 1         # 调用挂起等待配对

    # 把这一行补完：同一条链上配对成功
    with spool.open("a", encoding="utf-8") as fh:
        fh.write(full_result[20:] + "\n")
    report = import_spool(spool, chain=chain, state_path=state)
    assert report["records"] == 1 and report["chain_ok"] is True
    assert len(chain.load()) == 1


def test_bad_lines_are_counted_not_fatal(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = tmp_path / "dsh-events.jsonl"
    spool.write_text("not json\n" + json.dumps(_call()) + "\n"
                     + json.dumps(_result()) + "\n", encoding="utf-8")
    report = import_spool(spool, chain=chain, state_path=None)
    assert report["bad_lines"] == 1 and report["records"] == 1


def test_chain_stays_verifiable_after_import(tmp_path):
    """导入后链必须自校验通过——这是"可机验"的全部意义。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [_call("a"), _result("a"), _call("b"),
                              _result("b", is_error=True)])
    report = import_spool(spool, chain=chain, state_path=None)
    assert report["records"] == 2 and report["chain_ok"] is True
    assert chain.verify()["ok"] is True


def test_missing_spool_is_reported_not_fatal(tmp_path):
    report = import_spool(tmp_path / "nope.jsonl", chain=EvidenceChain(
        tmp_path / "chain.jsonl"), state_path=None)
    assert report["records"] == 0 and "spool 不存在" in report.get("note", "")


# ----------------------------------------------------------------------
# 插件侧（node）：不装 DSH 也能验"订阅 -> 落盘"这条链路本身
# ----------------------------------------------------------------------
def test_plugin_writes_spool_from_session_events(tmp_path):
    """用桩 ctx 直接跑插件：两个事件 -> 两行 spool，且字段对得上。"""
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("本机无 node，跳过宿主插件烟雾测试")

    spool = tmp_path / "spool.jsonl"
    script = f"""
import {{ apply }} from {json.dumps(PLUGIN.as_uri())};
const listeners = {{}};
const ctx = {{ on: (evt, fn) => {{ (listeners[evt] ||= []).push(fn); }} }};
apply(ctx, {{ spoolPath: {json.dumps(str(spool))} }});
if (!listeners['session/event']) throw new Error('未订阅 session/event');
const emit = (e) => listeners['session/event'].forEach((f) => f({{ header: {{ id: 's1' }} }}, e));
emit({{ type: 'tool/call', time: 1, data: {{ turn: 1, step: 1, callId: 'c1', name: 'pwsh', arguments: '{{"command":"ls"}}' }} }});
emit({{ type: 'tool/result', time: 2, data: {{ turn: 1, step: 1, message: {{ source: {{ kind: 'tool', callId: 'c1' }}, content: [{{ isError: false, content: 'ok-200' }}] }} }} }});
emit({{ type: 'assistant/message', time: 3, data: {{}} }});   // 无关事件：不落盘
console.log('PLUGIN_OK');
"""
    proc = subprocess.run([node, "--input-type=module", "-e", script],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60)
    assert "PLUGIN_OK" in proc.stdout, proc.stderr[:400]

    lines = [json.loads(x) for x in spool.read_text(encoding="utf-8").splitlines()]
    assert [x["kind"] for x in lines] == ["call", "result"]
    assert lines[0]["tool"] == "pwsh" and lines[0]["session"] == "s1"
    assert lines[1]["isError"] is False and "ok-200" in lines[1]["output"]
    # 结果行必须带上 callId（在 message.source.callId，真机踩过两次）
    assert lines[1]["callId"] == "c1"


def test_plugin_spool_feeds_the_chain(tmp_path):
    """端到端：插件产出的 spool 能直接喂给内核导入器并入链。"""
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("本机无 node，跳过宿主插件烟雾测试")

    spool = tmp_path / "spool.jsonl"
    script = f"""
import {{ apply }} from {json.dumps(PLUGIN.as_uri())};
const listeners = {{}};
const ctx = {{ on: (e, f) => {{ (listeners[e] ||= []).push(f); }} }};
apply(ctx, {{ spoolPath: {json.dumps(str(spool))} }});
const emit = (e) => listeners['session/event'].forEach((f) => f({{ header: {{ id: 's2' }} }}, e));
emit({{ type: 'tool/call', time: 1, data: {{ turn: 1, step: 2, callId: 'k1', name: 'http_raw', arguments: '{{"url":"http://127.0.0.1:3000/"}}' }} }});
emit({{ type: 'tool/result', time: 2, data: {{ turn: 1, step: 2, callId: 'k1', message: {{ content: [{{ isError: false, content: '200 text/html' }}] }} }} }});
"""
    subprocess.run([node, "--input-type=module", "-e", script],
                   capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60, check=True)

    chain = EvidenceChain(tmp_path / "chain.jsonl")
    report = import_spool(spool, chain=chain, state_path=None)
    assert report["records"] == 1 and report["chain_ok"] is True
    content = chain.load()[0].content
    assert content["tool"] == "http_raw"
    assert content["args"] == {"url": "http://127.0.0.1:3000/"}
    assert content["ok"] is True and "text/html" in content["output"]

def test_result_without_callid_pairs_by_turn_step(tmp_path):
    """真机教训：`tool/result` 可能取不到 callId——按 (turn, step) 唯一匹配。

    2026-09-21 真机跑出来的 spool 里，结果行 `callId` 是空串（它在
    `message.content[0].callId`，插件侧已修），当时记录丢了工具名与参数。
    """
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [
        _call(call_id="real-1", tool="pwsh", args='{"command":"echo hi"}'),
        _result(call_id="", output="hi"),          # 结果侧没有 callId
    ])
    report = import_spool(spool, chain=chain, state_path=None)

    assert report["records"] == 1 and report["open_calls"] == 0
    content = chain.load()[0].content
    assert content["tool"] == "pwsh"                    # 工具名没丢
    assert content["args"] == {"command": "echo hi"}
    assert content["call_id"] == "real-1"


def test_result_with_unknown_callid_single_pending_pairs(tmp_path):
    """callId 对不上但只有一个挂起项：用它（单工具会话常见）。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [
        _call(call_id="a", tool="http_raw"),
        _result(call_id="b", output="200"),
    ])
    import_spool(spool, chain=chain, state_path=None)
    content = chain.load()[0].content
    assert content["tool"] == "http_raw" and content["output"] == "200"

def test_policy_event_becomes_observation(tmp_path):
    """裁决事件（kind=policy）在链上留成 observation——"为什么被问/被拒"要可查。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = tmp_path / "dsh-events.jsonl"
    spool.write_text(json.dumps({
        "ts": 1, "kind": "policy", "tool": "pwsh", "decision": "ask",
        "hosts": ["127.0.0.1"], "outside": [],
        "reason": "目标动作建议走内核工具", "command": "curl http://127.0.0.1:3000/",
    }, ensure_ascii=False) + "\n", encoding="utf-8")

    report = import_spool(spool, chain=chain, state_path=None)
    assert report["records"] == 1 and report["chain_ok"] is True
    rec = chain.load()[0]
    assert rec.kind == "observation"
    assert rec.content["decision"] == "ask"
    assert rec.content["kind"] == "target_action_decision"
    assert rec.content["hosts"] == ["127.0.0.1"]


# ----------------------------------------------------------------------
# 裁决层（预执行策略）：只针对"对目标发请求的宿主 shell 命令"
# ----------------------------------------------------------------------
def _policy_call(tmp_path, tool, command, tool_names=None, **cfg):
    """用桩 ctx 跑一次 pre-execute，返回 (裁决, spool 记录列表)。

    `tool_names`：注入"该 agent 作用域里可见的工具名"。None = 拿不到工具服务
    （守卫必须判为 unknown 并按原档位走）；传列表则模拟真实会话的工具面——
    内核缺位就是"列表里没有任何 mcp__proteus__*"。
    """
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("本机无 node，跳过宿主插件策略测试")
    # 每次调用独立 spool——同一 tmp_path 里连着跑两次时不能串味
    import uuid

    spool = tmp_path / f"policy-{uuid.uuid4().hex[:8]}.jsonl"
    config = {"spoolPath": str(spool), **cfg}
    names_js = "null" if tool_names is None else json.dumps(tool_names)
    script = f"""
import {{ apply }} from {json.dumps(PLUGIN.as_uri())};
const listeners = {{}};
const names = {names_js};
const tools = names === null
  ? undefined
  : {{ schemas: () => names.map((n) => ({{ name: n }})) }};
const ctx = {{ on: (e, f) => {{ (listeners[e] ||= []).push(f); }}, tools }};
apply(ctx, {json.dumps(config, ensure_ascii=False)});
const hooks = listeners['tools/pre-execute'] || [];
const exec = {{ name: {json.dumps(tool)}, arguments: {{ command: {json.dumps(command)} }},
               agent: 'agent-stub' }};
const out = [];
for (const fn of hooks) {{
  const d = await fn(exec, async () => ({{ kind: 'allow' }}));
  out.push(JSON.stringify(d));
}}
console.log(out.join('|'));
"""
    proc = subprocess.run([node, "--input-type=module", "-e", script],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60)
    assert proc.returncode == 0, proc.stderr[:400]
    decisions = [json.loads(x) for x in proc.stdout.strip().split("|") if x]
    records = ([json.loads(ln) for ln in spool.read_text(encoding="utf-8").splitlines()]
               if spool.exists() else [])
    return decisions[0] if decisions else None, records


def test_policy_asks_on_shell_request_to_authorized_target(tmp_path):
    decision, records = _policy_call(
        tmp_path, "pwsh", "curl http://127.0.0.1:3000/ -s")
    assert decision["kind"] == "ask"
    assert "内核工具" in decision["reason"]
    assert records[-1]["kind"] == "policy" and records[-1]["hosts"] == ["127.0.0.1"]


def test_policy_asks_on_out_of_scope_target(tmp_path):
    """越界目标：同样 ask，但理由不同（白名单不会放行）——默认档位是 ask。"""
    decision, records = _policy_call(
        tmp_path, "pwsh", "nmap -sV 203.0.113.10")
    assert decision["kind"] == "ask"
    assert "不在内核授权白名单" in decision["reason"]
    assert records[-1]["outside"] == ["203.0.113.10"]


def test_policy_allows_local_only_command(tmp_path):
    """本地命令（echo/文件操作）不打扰。"""
    decision, records = _policy_call(tmp_path, "pwsh", "echo hello > out.txt")
    assert decision["kind"] == "allow"
    assert records == []


def test_policy_allows_kernel_and_other_tools(tmp_path):
    """内核工具（已过内核闸门）与无关工具一律放行。"""
    kernel, _ = _policy_call(tmp_path, "mcp__proteus__http_raw",
                             "curl http://127.0.0.1:3000/")
    other, _ = _policy_call(tmp_path, "read", "curl http://127.0.0.1:3000/")
    assert kernel["kind"] == "allow" and other["kind"] == "allow"


def test_policy_deny_mode_and_off_mode(tmp_path):
    denied, _ = _policy_call(tmp_path, "pwsh", "curl http://127.0.0.1:3000/",
                             mode="deny")
    assert denied["kind"] == "deny" and "内核工具" in denied["reason"]

    # off：**不注册裁决**（不是返回 allow）——注册表默认放行，等于只审计不干预
    off, off_records = _policy_call(tmp_path, "pwsh",
                                    "curl http://127.0.0.1:3000/", mode="off")
    assert off is None and off_records == []

def test_role_audit_and_policy_register_separately(tmp_path):
    """`role` 分工：audit 只订阅事件、policy 只挂裁决——两个挂载点不重复记录。

    背景（2026-09-22 真机）：DSH 的工具派发是作用域过滤的，host 平面的
    `tools/pre-execute` 收不到 preset 作用域内的调用，所以裁决行必须挂进
    preset；审计（session/event）是全局事件，留在 host 平面。同一份实现由
    `role` 分工，避免两条挂载点各记一份。
    """
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("本机无 node，跳过宿主插件 role 测试")
    for role, want_event, want_policy in (("audit", True, False),
                                          ("policy", False, True),
                                          ("both", True, True)):
        spool = tmp_path / f"role-{role}.jsonl"
        script = f"""
import {{ apply }} from {json.dumps(PLUGIN.as_uri())};
const seen = [];
const ctx = {{ on: (e) => seen.push(e) }};
apply(ctx, {{ spoolPath: {json.dumps(str(spool))}, role: {json.dumps(role)} }});
console.log(JSON.stringify(seen));
"""
        proc = subprocess.run([node, "--input-type=module", "-e", script],
                              capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60)
        assert proc.returncode == 0, proc.stderr[:300]
        registered = json.loads(proc.stdout.strip())
        assert ("session/event" in registered) is want_event, role
        assert ("tools/pre-execute" in registered) is want_policy, role

# ----------------------------------------------------------------------
# preset 归属（R-22）：session/event 是全局事件，必须能分辨"这条链是谁的"
# ----------------------------------------------------------------------
def _audit_call(tmp_path, session, event, **cfg):
    """用桩 ctx 跑一次 session/event，返回 spool 记录列表。"""
    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("本机无 node，跳过宿主插件审计测试")
    import uuid

    spool = tmp_path / f"audit-{uuid.uuid4().hex[:8]}.jsonl"
    config = {"spoolPath": str(spool), "role": "audit", **cfg}
    script = f"""
import {{ apply }} from {json.dumps(PLUGIN.as_uri())};
const listeners = {{}};
const ctx = {{ on: (e, f) => {{ (listeners[e] ||= []).push(f); }} }};
apply(ctx, {json.dumps(config, ensure_ascii=False)});
for (const fn of (listeners['session/event'] || [])) {{
  fn({json.dumps(session, ensure_ascii=False)}, {json.dumps(event, ensure_ascii=False)});
}}
console.log('ok');
"""
    proc = subprocess.run([node, "--input-type=module", "-e", script],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60)
    assert proc.returncode == 0, proc.stderr[:400]
    if not spool.exists():
        return []
    return [json.loads(ln)
            for ln in spool.read_text(encoding="utf-8").splitlines()
            if ln.strip()]


def _call_event(call_id="c1", tool="http_raw", url="http://127.0.0.1:3000/"):
    return {"type": "tool/call", "time": 1,
            "data": {"turn": 1, "step": 1, "callId": call_id, "name": tool,
                     "arguments": json.dumps({"url": url})}}


def test_audit_records_carry_preset_ownership(tmp_path):
    """每条审计记录都带 preset 归属（取 SessionHeader.agentPreset）。"""
    records = _audit_call(
        tmp_path, {"header": {"id": "s1", "agentPreset": "proteus"}},
        _call_event())
    assert len(records) == 1
    assert records[0]["preset"] == "proteus"
    assert records[0]["session"] == "s1" and records[0]["kind"] == "call"


def test_audit_preset_filter_skips_other_presets(tmp_path):
    """`presets: ['proteus']`：别的 preset 的会话不进 spool。"""
    skipped = _audit_call(
        tmp_path, {"header": {"id": "s2", "agentPreset": "liangshen"}},
        _call_event(), presets=["proteus"])
    assert skipped == []

    kept = _audit_call(
        tmp_path, {"header": {"id": "s1", "agentPreset": "proteus"}},
        _call_event(), presets=["proteus"])
    assert len(kept) == 1 and kept[0]["preset"] == "proteus"


def test_audit_preset_filter_keeps_unknown_ownership(tmp_path):
    """归属未知（会话头没这个字段）**必须保留**——静默丢审计比多留危险得多。"""
    records = _audit_call(
        tmp_path, {"header": {"id": "s3"}}, _call_event(), presets=["proteus"])
    assert len(records) == 1
    assert records[0]["preset"] == ""


def test_policy_record_includes_preset_field(tmp_path):
    """裁决记录也带 preset 字段（pre-execute 载荷里没有 session，取不到就是 ''）。"""
    _, records = _policy_call(tmp_path, "pwsh", "curl http://127.0.0.1:3000/")
    assert "preset" in records[-1]


def test_importer_carries_preset_into_chain(tmp_path):
    """归属要进证据链，否则消费端没法按 preset 过滤。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = _spool(tmp_path, [
        _call(call_id="p1", tool="http_raw", preset="proteus"),
        _result(call_id="p1", output="200"),
    ])
    import_spool(spool, chain=chain, state_path=None)
    assert chain.load()[0].content["preset"] == "proteus"


def test_importer_policy_preset_reaches_the_chain(tmp_path):
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = tmp_path / "dsh-events.jsonl"
    spool.write_text(json.dumps({
        "ts": 1, "kind": "policy", "tool": "pwsh", "decision": "ask",
        "hosts": ["127.0.0.1"], "outside": [], "kernel": "yes",
        "preset": "proteus", "reason": "目标动作建议走内核工具",
        "command": "curl http://127.0.0.1:3000/",
    }, ensure_ascii=False) + "\n", encoding="utf-8")

    import_spool(spool, chain=chain, state_path=None)
    assert chain.load()[0].content["preset"] == "proteus"


# ----------------------------------------------------------------------
# 内核缺位守卫：MCP 行没起来时，目标动作收紧（fail-closed）
#
# 为什么必须有：MCP 行配的是 failOnStartupError: false —— 内核起不来时 preset
# 照常挂载、只是没有那组工具、且界面上没有任何提示。那种会话里"对目标发请求"
# 既无模式闸门也无证据链，放行等于"为能用而放弃保护"。
# ----------------------------------------------------------------------
HOST_TOOLS = ["pwsh", "read", "write"]


def test_kernel_guard_denies_target_action_when_kernel_missing(tmp_path):
    """内核缺位 + 缺省档：直接拒绝，且理由给可操作的修复路径。"""
    decision, records = _policy_call(
        tmp_path, "pwsh", "curl http://127.0.0.1:3000/", tool_names=HOST_TOOLS)
    assert decision["kind"] == "deny"
    assert "内核工具未挂载" in decision["reason"]
    assert "dsh_install.py --check" in decision["reason"]
    assert records[-1]["decision"] == "deny" and records[-1]["kernel"] == "missing"


def test_kernel_guard_keeps_normal_tier_when_kernel_present(tmp_path):
    """内核在（工具面里有 mcp__proteus__*）→ 回到常规 ask 档。"""
    decision, records = _policy_call(
        tmp_path, "pwsh", "curl http://127.0.0.1:3000/",
        tool_names=HOST_TOOLS + ["mcp__proteus__http_raw"])
    assert decision["kind"] == "ask"
    assert "内核工具未挂载" not in decision["reason"]
    assert records[-1]["kernel"] == "yes"


def test_kernel_guard_unknown_does_not_change_behavior(tmp_path):
    """拿不到工具服务 → unknown → 按原档位走。

    DSH 是 pre-stable：把"API 形状变了"误判成"内核没了"，会把健康会话整片
    拒掉，比漏拦更糟。所以未知一律不参与裁决。
    """
    decision, records = _policy_call(tmp_path, "pwsh",
                                     "curl http://127.0.0.1:3000/")
    assert decision["kind"] == "ask"
    assert records[-1]["kernel"] == "unknown"


def test_kernel_guard_warn_mode_only_warns(tmp_path):
    decision, records = _policy_call(
        tmp_path, "pwsh", "curl http://127.0.0.1:3000/",
        tool_names=HOST_TOOLS, kernelGuard="warn")
    assert decision["kind"] == "ask"
    assert "内核工具未挂载" in decision["reason"]
    assert records[-1]["kernel"] == "missing"


def test_kernel_guard_off_restores_plain_tier(tmp_path):
    decision, _ = _policy_call(
        tmp_path, "pwsh", "curl http://127.0.0.1:3000/",
        tool_names=HOST_TOOLS, kernelGuard="off")
    assert decision["kind"] == "ask"
    assert "内核工具未挂载" not in decision["reason"]


def test_kernel_guard_leaves_local_commands_alone(tmp_path):
    """守卫只作用于"对目标发请求"的命令——内核缺位时本地操作照常。"""
    decision, records = _policy_call(
        tmp_path, "pwsh", "echo hi > out.txt", tool_names=HOST_TOOLS)
    assert decision["kind"] == "allow" and records == []


def test_kernel_guard_prefix_is_configurable(tmp_path):
    """前缀可配：换 MCP serverName 时守卫要跟着走，不能写死。"""
    decision, _ = _policy_call(
        tmp_path, "pwsh", "curl http://127.0.0.1:3000/",
        tool_names=HOST_TOOLS + ["mcp__other__x"],
        kernelToolPrefix="mcp__other__")
    assert decision["kind"] == "ask"


def test_policy_kernel_field_reaches_the_chain(tmp_path):
    """内核缺位标记要能进证据链——否则链上分不清"被闸门拦"与"内核没起来"。"""
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    spool = tmp_path / "dsh-events.jsonl"
    spool.write_text(json.dumps({
        "ts": 1, "kind": "policy", "tool": "pwsh", "decision": "deny",
        "hosts": ["127.0.0.1"], "outside": [], "kernel": "missing",
        "reason": "目标动作已按 fail-closed 拒绝",
        "command": "curl http://127.0.0.1:3000/",
    }, ensure_ascii=False) + "\n", encoding="utf-8")

    import_spool(spool, chain=chain, state_path=None)
    content = chain.load()[0].content
    assert content["kernel"] == "missing"
    assert content["decision"] == "deny"


def test_path_spelling_does_not_duplicate(tmp_path, monkeypatch):
    """同一 spool 用相对/绝对两种写法调用，不能重复入链。

    2026-09-22 真机发现：CLI 传相对路径、评分卡套件传绝对路径，状态文件里
    记的 `spool` 字符串对不上就从头重放——链上出现 16 个 call_id 各有两条记录。
    修法是路径先 resolve() 再比较与存储。
    """
    chain = EvidenceChain(tmp_path / "chain.jsonl")
    state = tmp_path / "state.json"
    spool = _spool(tmp_path, [_call("p1"), _result("p1")])

    monkeypatch.chdir(tmp_path)
    first = import_spool("dsh-events.jsonl", chain=chain, state_path=state)
    second = import_spool(str(spool.resolve()), chain=chain, state_path=state)
    assert first["records"] == 1 and second["records"] == 0
    assert len(chain.load()) == 1
