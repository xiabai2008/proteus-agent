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
