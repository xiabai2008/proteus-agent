"""人读的作战记录 / 证据链汇总（MCP 工具与 CLI 共用，一份实现）。

给两个入口用：
  - MCP 工具 `pentest_evidence`（模型在会话里直接调）
  - CLI `python -m penagent evidence`（DSH /proteus-evidence 命令插件 shell 它）

输出纯文本：命令面板与聊天消息都能直接展示。另有 `sarif_report`（P1-1）：
把同一条证据链导成 SARIF 2.1.0，给 CI/工单系统消费。
"""
from __future__ import annotations

import json
from pathlib import Path

from penagent.evidence import EvidenceChain
from penagent.memory import Memory


def _mission_detail(m: dict) -> str:
    lines = [
        f"任务 {m.get('id', '?')} · {m.get('outcome', '?')}",
        f"  目标: {m.get('target', '')}",
        f"  任务: {m.get('objective', '')}",
        f"  时间: {m.get('started_at', '')} → "
        f"{m.get('finished_at') or '进行中'}",
    ]
    steps = m.get("steps") or []
    if steps:
        lines.append(f"  步骤（{len(steps)}）:")
        for s in steps[-12:]:
            lines.append(f"    #{s.get('step')} {s.get('tool', '?')} "
                         f"{'OK' if s.get('ok') else 'FAIL'}")
    summary = str(m.get("reflection") or "").strip()
    if summary:
        lines.append(f"  结论: {summary[:300]}")
    return "\n".join(lines)


SARIF_LEVELS = {"conclusion": "warning", "observation": "note",
                "decision": "note", "tool_call": "none"}


def _digest(text: str) -> str:
    import hashlib

    return hashlib.sha256(str(text).encode("utf-8", errors="replace")) \
        .hexdigest()[:12]


def _all_missions(data_dir: str) -> list[dict]:
    """跨分区收集作战记录（P2-3 顺带修的盲区）。

    作战记录按 `memory_namespace` 分区（模式各写各的），而 `Memory(data)` 默认
    只看 `default` 分区——于是"跑过 ctf-crypto 任务却一条记录都列不出来"。
    视图要的是"全部任务"，所以按分区扫一遍并给每条记录补 `namespace` 便于显示。
    """
    from penagent.memory import Memory

    base = Memory(data_dir)
    out: list[dict] = []
    for namespace in base.namespaces() or [base.namespace]:
        for mission in Memory(data_dir, namespace=namespace).list_missions():
            record = dict(mission)
            record.setdefault("namespace", namespace)
            out.append(record)
    return out


def mission_tree(data_dir: str, mission_id: str = "") -> dict:
    """把**扁平**证据链投影成 Task → Action → Artifact 三层（P2-3）。

    为什么要这层视图（借 PentAGI 的 Flow→Task→Action→Artifact）：链本身只有
    seq/kind/content，人能读单条、看不出"这次任务做了哪几步、每步产出什么、
    结论引用了哪一条"。层级视图回答的正是这三个问题。

    层级依据是链记录里的 `mission`/`step` 字段（P2-3 起由 `_append_evidence`
    写入）——**没有任务归属的老链不丢**：单独列在 `unlinked` 里（宁可多留，
    与审计桥的"归属未知不过滤"同源）。

    Action 与 Artifact 的对应走两条路：① 作战记录步骤里的 `evidence_seq`
    （权威）；② 记录自身的 `mission` 字段（老链兜底）。
    """
    from penagent.evidence import EvidenceChain

    chain = EvidenceChain(Path(data_dir) / "chain.jsonl")
    verify = chain.verify()
    records = chain.load()
    by_seq = {r.seq: r for r in records}

    all_missions = _all_missions(data_dir)
    if mission_id:
        missions = [m for m in all_missions if str(m.get("id", "")) == mission_id]
    else:
        missions = sorted(all_missions,
                          key=lambda m: str(m.get("started_at", "")))

    # 按任务归属分组链记录（无归属的单独留档）
    grouped: dict[str, list] = {}
    unlinked: list[dict] = []
    for record in records:
        owner = str((record.content or {}).get("mission", "") or "")
        if owner:
            grouped.setdefault(owner, []).append(record)
        elif record.kind in ("tool_call", "conclusion", "decision"):
            unlinked.append({"seq": record.seq, "kind": record.kind})

    tasks = []
    for mission in missions:
        mid = str(mission.get("id", ""))
        owned = grouped.get(mid, [])
        # 结论与引用集合
        conclusions = [r for r in owned if r.kind == "conclusion"]
        if not conclusions:
            # 老链兜底（P2-3 之前的链没有 mission 字段）：按结论正文与任务
            # 自述**精确相等**认领——不是按 seq 区间猜，区间在并发/分叉
            # 时会张冠李戴。（任务自述落在 `reflection` 字段上，`summary`
            # 只是链上的名字，两者都要认。）
            wanted = {str(mission.get("summary") or ""),
                      str(mission.get("reflection") or "")} - {""}
            if wanted:
                conclusions = [
                    r for r in records if r.kind == "conclusion"
                    and not str((r.content or {}).get("mission") or "")
                    and str((r.content or {}).get("summary") or "") in wanted]
        cited: set[int] = set()
        for rec in conclusions:
            cited |= {int(x) for x in (rec.content.get("evidence_refs") or [])}
        # 作废记录：seq → tool_call 记录（同时兜住"记录没带 mission"的老链）
        calls_by_seq = {r.seq: r for r in records if r.kind == "tool_call"
                        and str((r.content or {}).get("mission", "") or "")
                        in ("", mid)}
        wanted_refs = {int(x) for x in (mission.get("evidence_refs") or [])}
        cited |= wanted_refs

        actions = []
        seen_seq: set[int] = set()
        for index, step_rec in enumerate(mission.get("steps") or [], 1):
            seq = step_rec.get("evidence_seq")
            record = by_seq.get(seq) if isinstance(seq, int) else None
            if record is None:
                # 老链兜底：按 (mission, step) 找
                for rec in owned:
                    if rec.kind == "tool_call" and \
                            rec.content.get("step") == step_rec.get("step"):
                        record = rec
                        break
            content = dict(record.content) if record is not None else {}
            if record is not None:
                seen_seq.add(record.seq)
            output = str(content.get("output", "") or "")
            actions.append({
                "step": step_rec.get("step", index),
                "tool": str(step_rec.get("tool", "") or content.get("tool", "")),
                "ok": step_rec.get("ok", content.get("ok")),
                "blocked": bool(content.get("blocked")),
                "reason": str(content.get("reason", "")
                              or content.get("error", ""))[:200],
                "evidence_seq": record.seq if record is not None else None,
                "artifacts": ([{
                    "seq": record.seq,
                    "kind": record.kind,
                    "digest": _digest(output or str(content.get("error", ""))),
                    "chars": len(output),
                    "cited": record.seq in cited,
                }] if record is not None else []),
            })
        tasks.append({
            "id": mid,
            "namespace": mission.get("namespace", ""),
            "target": mission.get("target", ""),
            "objective": mission.get("objective", ""),
            "outcome": mission.get("outcome", ""),
            "started_at": mission.get("started_at", ""),
            "finished_at": mission.get("finished_at", ""),
            "summary": str(mission.get("summary") or
                           mission.get("reflection") or "")[:300],
            "evidence_refs": sorted(cited),
            "actions": actions,
            "conclusions": [{
                "seq": rec.seq,
                "phase": str((rec.content or {}).get("phase", "") or "concluded"),
                "verdict": str((rec.content or {}).get("verdict", ""))[:200],
                "summary": str((rec.content or {}).get("summary", ""))[:200],
            } for rec in conclusions],
            "unattributed_records": [r.seq for r in owned
                                     if r.seq not in seen_seq
                                     and r.kind != "conclusion"],
        })

    return {"chain_length": verify["length"], "chain_ok": bool(verify["ok"]),
            "tasks": tasks, "unlinked": unlinked}


def render_tree(tree: dict) -> str:
    """层级视图的人读形态（CLI 与 /proteus-tree 共用）。"""
    lines = [f"证据链：{tree['chain_length']} 条 · "
             f"校验 {'通过' if tree['chain_ok'] else '不通过'}"]
    if not tree["tasks"]:
        lines.append("（没有作战记录——层级视图以任务为单位）")
    for task in tree["tasks"]:
        lines.append("")
        lines.append(f"任务 {task['id']} · {task['outcome']} · "
                     f"{task['target']}"
                     f"{(' · 分区 ' + task['namespace']) if task.get('namespace') else ''}")
        lines.append(f"  目标: {str(task['objective'])[:80]}")
        lines.append(f"  时间: {task['started_at']} → "
                     f"{task['finished_at'] or '进行中'}"
                     f" · 证据引用 {task['evidence_refs'] or '（无）'}")
        for action in task["actions"]:
            mark = "拦" if action["blocked"] else \
                ("OK" if action["ok"] else "FAIL")
            seq = action["evidence_seq"]
            lines.append(f"  ├─ #{action['step']} {action['tool']} [{mark}]"
                         f" evidence_seq={seq}")
            for art in action["artifacts"]:
                lines.append(f"  │    artifact seq={art['seq']} "
                             f"sha={art['digest']} {art['chars']}字符"
                             f"{'（被结论引用）' if art['cited'] else ''}")
            if action["reason"]:
                lines.append(f"  │    理由: {action['reason'][:100]}")
        for concl in task["conclusions"]:
            lines.append(f"  └─ 结论 seq={concl['seq']}（{concl['phase']}）: "
                         f"{concl['summary'][:120]}")
        if task["unattributed_records"]:
            lines.append(f"  （本任务名下有 {len(task['unattributed_records'])}"
                         f" 条未挂到步骤的记录："
                         f"{task['unattributed_records'][:8]}）")
    if tree["unlinked"]:
        lines.append("")
        lines.append(f"未归属记录 {len(tree['unlinked'])} 条"
                     f"（宿主会话 / 历史任务，不静默丢）："
                     f"{[u['seq'] for u in tree['unlinked'][:10]]}")
    return "\n".join(lines)


def sarif_report(data_dir: str, mission_id: str = "") -> dict:
    """把证据链导成 SARIF 2.1.0（标准容器，CI/工单系统可直接消费）。

    **诚实界定**：SARIF 是静态分析/告警的通用容器，我们的证据链不是漏洞清单
    ——所以这里的映射是"一条证据 = 一条 result"，`ruleId` 用证据类型
    （`proteus/<kind>`），正文装证据内容（截断）。它**不是**"漏洞报告"，
    漏洞结论要由人/模型基于 `evidence_refs` 写出来。

    为什么要它：结论要能进 CI、进工单、进别的工具链；自研格式做不到。
    借 Strix 的做法（`findings.sarif`），让"可机验"落在一个通用格式上。
    """
    from penagent.evidence import EvidenceChain

    chain = EvidenceChain(Path(data_dir) / "chain.jsonl")
    records = chain.load()
    verify = chain.verify()

    results = []
    rules: dict[str, dict] = {}
    for rec in records:
        rule_id = f"proteus/{rec.kind or 'record'}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rec.kind or "record",
            "shortDescription": {"text": f"Proteus 证据类型：{rec.kind}"},
        })
        content = rec.content if isinstance(rec.content, dict) else {}
        target = ""
        for key in ("target", "url", "host", "domain"):
            if content.get(key):
                target = str(content[key])[:300]
                break
        message = json.dumps(content, ensure_ascii=False)[:1000]
        result = {
            "ruleId": rule_id,
            "level": SARIF_LEVELS.get(rec.kind, "note"),
            "message": {"text": message},
            "properties": {"seq": rec.seq, "kind": rec.kind,
                           "hash": rec.hash[:16],
                           "timestamp": rec.timestamp,
                           "mission": str(content.get("mission", ""))},
        }
        if target:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target}}}]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "proteus-agent",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "invocations": [{
                "executionSuccessful": bool(verify.get("ok")),
                "properties": {
                    "mission": mission_id,
                    "chain_length": verify.get("length"),
                    "chain_ok": bool(verify.get("ok")),
                    "tampered": verify.get("tampered") or [],
                    "broken_links": verify.get("broken_links") or [],
                },
            }],
            "results": results,
        }],
    }


def evidence_report(data_dir: str, mission_id: str = "") -> str:
    """汇总：证据链校验 + 最近任务列表（或指定任务的明细）。"""
    mem = Memory(data_dir)
    chain = EvidenceChain(Path(data_dir) / "chain.jsonl")
    verify = chain.verify()
    lines = [f"证据链：{verify['length']} 条记录 · "
             f"校验 {'通过' if verify['ok'] else '不通过'}"]
    if not verify["ok"]:
        lines.append(f"  篡改序号 {verify['tampered']} · "
                     f"断链序号 {verify['broken_links']}")

    if mission_id:
        try:
            m = mem.get_mission(mission_id)
        except (FileNotFoundError, ValueError):
            lines += ["", f"任务 {mission_id} 不存在（用无参数形式看最近任务列表）"]
            return "\n".join(lines)
        lines += ["", _mission_detail(m)]
        return "\n".join(lines)

    missions = mem.list_missions()
    if not missions:
        lines += ["", "暂无作战记录。"]
        return "\n".join(lines)
    lines += ["", f"最近任务（共 {len(missions)} 条，显示最近 10）:"]
    for m in sorted(missions, key=lambda x: x.get("started_at", ""))[-10:]:
        lines.append(
            f"  {m.get('id', '?')} · {m.get('outcome', '?'):<8} · "
            f"{len(m.get('steps') or [])} 步 · {m.get('target', '')} · "
            f"{str(m.get('objective', ''))[:40]}")
    return "\n".join(lines)
