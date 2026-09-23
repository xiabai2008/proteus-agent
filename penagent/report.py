"""人读的作战记录 / 证据链汇总（MCP 工具与 CLI 共用，一份实现）。

给两个入口用：
  - MCP 工具 `pentest_evidence`（模型在会话里直接调）
  - CLI `python -m penagent evidence`（DSH /proteus-evidence 命令插件 shell 它）

输出纯文本：命令面板与聊天消息都能直接展示。
"""
from __future__ import annotations

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
