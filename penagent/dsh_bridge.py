"""DSH 会话事件 -> 内核证据链（宿主侧旁路治理的审计通道）。

背景：2026-09-21 的真机实测发现，DSH 会话里模型可能绕开 `mcp__proteus__*`、
直接用宿主 shell 干活——那种情况下内核的证据链/记忆/技能全部空转，结论
不可机验。治理方案见 `docs/DSH插件化与内核旁路治理.md`：宿主侧用 bundle
插件（`dsh/proteus-bridge`）把每次工具调用写进 spool，本模块把 spool **并入
内核的链式哈希证据链**。

两条刻意的边界：

1. **链式哈希只在内核实现一份**（硬规则 2）：插件只落原始事件，哈希与链接
   由 `penagent/evidence.py` 的 `EvidenceChain` 完成——同一语义不做两份实现。
2. **调用与结果配对成一条记录**：DSH 事件是 `tool/call` / `tool/result` 两条，
   而内核的证据记录形状是 `{tool, args, ok, output}`（评测判定 `score_from_evidence`
   与判定器都按这个读）。这里按 `callId` 配对合并，让宿主会话与内核自有会话
   在证据链里形状一致——评测口径因此可以统一。

增量导入：状态文件记录已消费的字节偏移，重复运行不会重复入链；`replay=True`
时从头重放（用于换链重建）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from penagent.evidence import EvidenceChain

DEFAULT_SPOOL = Path("data/dsh-events.jsonl")
DEFAULT_STATE = Path("data/dsh-spool.state.json")


def _parse_args(raw: Any) -> Any:
    """DSH 的 `arguments` 是字符串（多数工具是 JSON）；解析不了就原样留着。"""
    if not isinstance(raw, str):
        return raw if raw is not None else {}
    text = raw.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return raw


def _read_new_lines(spool: Path, offset: int) -> tuple[list[str], int]:
    """按字节偏移读新增行，返回 (lines, 新偏移)。残行不回退——下次再读。"""
    with spool.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
    if not chunk:
        return [], offset
    text = chunk.decode("utf-8", errors="replace")
    if not text.endswith("\n"):
        # 最后一行可能正被写入：只消费到最后一个换行为止
        cut = text.rfind("\n")
        if cut < 0:
            return [], offset
        text = text[:cut + 1]
        consumed = len(text.encode("utf-8"))
    else:
        consumed = len(chunk)
    return [ln for ln in text.splitlines() if ln.strip()], offset + consumed


def _pair_result(pending: dict[str, dict], event: dict,
                 call_id: str) -> tuple[Optional[dict], str]:
    """给结果事件找它对应的调用记录，返回 (调用, 实际用的 key)。

    三级匹配，逐级放宽——真机实测发现 `tool/result` 的 callId 可能取不到
    （它在 `message.content[0].callId`，插件侧已修，但历史 spool 与上游
    形状变化都要能兜住）：

    1. callId 精确匹配；
    2. callId 缺失/不匹配时，按 (turn, step) 找唯一候选；
    3. 仍不唯一但**只有一个挂起项**时用它（单工具会话的常见情形）。
    """
    if call_id and call_id in pending:
        return pending.pop(call_id), call_id
    turn, step = event.get("turn"), event.get("step")
    same_step = [k for k, v in pending.items()
                 if v.get("turn") == turn and v.get("step") == step]
    if len(same_step) == 1:
        key = same_step[0]
        return pending.pop(key), key
    if len(pending) == 1:
        key = next(iter(pending))
        return pending.pop(key), key
    return None, call_id


def import_spool(spool: str | Path = DEFAULT_SPOOL,
                 chain: Optional[EvidenceChain] = None,
                 chain_path: str | Path = "data/chain.jsonl",
                 state_path: Optional[str | Path] = DEFAULT_STATE,
                 replay: bool = False,
                 flush_open: bool = False) -> dict:
    """把 spool 里的新事件并入证据链，返回统计。

    - `chain` 显式传入时用调用方的链（测试用）；否则按 `chain_path` 新建。
    - `state_path=None` 表示不落状态（每次全量）；`replay=True` 忽略旧偏移。
    - **未配对的调用挂起、跨导入持久化**：结果随后到达时要能配上对——立即
      记账会产生"同一次调用两条记录"的假象。`flush_open=True` 才把挂起项
      按 `ok=None` 落链（用于会话已结束、结果永远不来的场景）。
    """
    # **路径必须先归一**：CLI 传相对路径、评分卡传绝对路径，同一个 spool 会因
    # 字符串不同而被当成两个文件 → 状态里的偏移失效 → 从头重放、链上出现
    # 同一次调用的两条记录（2026-09-22 真机发现，链上 16 个 call_id 重复）
    spool_path = Path(spool).resolve()
    chain_path = Path(chain_path).resolve()
    result = {"spool": str(spool_path), "lines": 0, "records": 0,
              "open_calls": 0, "bad_lines": 0, "chain": "", "chain_ok": None,
              "flushed": 0}
    if not spool_path.exists():
        result["note"] = "spool 不存在（宿主桥未启用或还没有工具调用）"
        return result

    offset = 0
    pending: dict[str, dict] = {}
    state_file = Path(state_path) if state_path else None
    if state_file and state_file.exists() and not replay:
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if str(state.get("spool", "")) == str(spool_path):
                offset = int(state.get("offset", 0))
                raw_pending = state.get("pending") or {}
                if isinstance(raw_pending, dict):
                    pending = {str(k): v for k, v in raw_pending.items()
                               if isinstance(v, dict)}
        except (OSError, ValueError):
            offset, pending = 0, {}

    lines, new_offset = _read_new_lines(spool_path, offset)
    chain = chain if chain is not None else EvidenceChain(chain_path)

    appended = 0
    bad = 0
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        call_id = str(event.get("callId") or "")
        kind = event.get("kind")
        if kind == "policy":
            # 宿主桥的目标动作裁决记录：留痕"为什么被问/被拒"（observation）
            chain.append("observation", {
                "source": "dsh",
                "kind": "target_action_decision",
                "decision": str(event.get("decision") or ""),
                "tool": str(event.get("tool") or ""),
                "hosts": event.get("hosts") or [],
                "outside": event.get("outside") or [],
                "reason": str(event.get("reason") or "")[:500],
                "command": str(event.get("command") or "")[:300],
                # 内核当时在不在：缺位时目标动作会被 fail-closed 拒绝，这条字段
                # 让链上能区分"被闸门拦下"与"内核根本没起来"（2026-09-22）
                "kernel": str(event.get("kernel") or ""),
                "ts": event.get("ts"),
            })
            appended += 1
            continue
        if kind == "call":
            pending[call_id] = event
            continue
        if kind != "result":
            bad += 1
            continue
        call, matched_key = _pair_result(pending, event, call_id)
        chain.append("tool_call", {
            "tool": str((call or {}).get("tool") or event.get("tool") or ""),
            "args": _parse_args((call or {}).get("args")),
            "ok": None if event.get("isError") is None
                  else (not event.get("isError")),
            "output": str(event.get("output") or "")[:4000],
            "source": "dsh",
            "session": event.get("session", ""),
            "turn": event.get("turn"),
            "step": event.get("step"),
            "call_id": call_id or matched_key,
            "error": str(event.get("error") or "")[:500],
            **({} if call is not None else
               {"note": "未找到对应调用（callId 缺失且无法按 turn/step 唯一匹配）"}),
        })
        appended += 1

    flushed = 0
    if flush_open:
        for call_id, call in pending.items():
            chain.append("tool_call", {
                "tool": str(call.get("tool") or ""),
                "args": _parse_args(call.get("args")),
                "ok": None,
                "output": "",
                "source": "dsh",
                "session": call.get("session", ""),
                "turn": call.get("turn"),
                "step": call.get("step"),
                "call_id": call_id,
                "note": "spool 里没有对应结果（会话中断或仍在执行）",
            })
            flushed += 1
        pending = {}

    if state_file is not None:
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            state_file.write_text(json.dumps(
                {"spool": str(spool_path), "offset": new_offset,
                 "pending": pending}, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:                        # 状态写不进去不该阻断
            result["state_error"] = str(exc)[:200]

    verify = chain.verify()
    result.update({
        "lines": len(lines),
        "records": appended,
        "flushed": flushed,
        "open_calls": len(pending),
        "bad_lines": bad,
        "chain": str(getattr(chain, "path", chain_path)),
        "chain_ok": bool(verify.get("ok")),
        "chain_length": verify.get("length"),
    })
    return result
