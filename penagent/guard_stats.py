"""宿主会话守卫与声明统计（路线图 P2-2，2026-09-27）。

**为什么**：宿主会话的守卫参数（`sameToolLimit` / `totalLimit`）此前只能凭感觉调
——而它们已经两次直接影响结果：首测那次 60 的总闸门掐断了正在逼近正确的纠正性
调用；重测那次同指纹守卫拦下两条重复调用（拦对了）。要调参，得先看得见。

**输入**：
- 宿主事件 spool（`data/dsh-events.jsonl`，host 平面审计行写）：每次工具调用 /
  结果 / 目标动作裁决（policy）/ 守卫干预（supervisor）；
- 证据链（`data/chain.jsonl`）：P2-1 的 `flag_claim` 声明记录；
- 作战记录（`data/missions/<分区>/`）：把声明归到模式 / 题目。

**输出**（按 preset 分组）：
- 会话数 / 调用数 / 工具失败数；
- 裁决分布：policy allow/ask/deny、supervisor deny/ask；
- **同指纹重复率**（守卫调参的直接依据：真循环 vs 正常重试）；
- 每会话调用数的 p50 / p90 / max（判断总闸门该定在哪）；
- **flag 声明**：claim 数、verified 数 → **假声明率**（声称解出但判定器不接受）。

一条命令：`python -m penagent guards --data data [--preset proteus*]`。
评分卡里对应 `dsh-session` 套件的 `guard-stats` 一行（观测行，不参与通过率）。
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Optional


def read_spool(path: str | Path) -> list[dict]:
    """读宿主事件 spool（每行一个 JSON；坏行跳过——审计通道 fail-open）。"""
    records: list[dict] = []
    p = Path(path)
    if not p.is_file():
        return records
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _match_preset(preset: str, patterns: str) -> bool:
    """preset 过滤：支持 fnmatch 家族通配（与评分卡 `--preset` 同口径）。"""
    import fnmatch

    if not patterns:
        return True
    return any(fnmatch.fnmatch(preset, pat.strip())
               for pat in str(patterns).split(",") if pat.strip())


def _pct(values: list[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return ordered[idx]


def _fingerprint(record: dict) -> str:
    tool = str(record.get("tool") or "")
    args = record.get("args")
    return f"{tool}::{args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)}"


def summarize(records: Iterable[dict], claims: Optional[list[dict]] = None,
              preset: str = "") -> dict:
    """把 spool 记录汇总成分组统计（纯函数：不碰文件，判据可被单测钉住）。

    `claims`：`[{"flag", "verified", "namespace"}]`（由 `claim_facts` 从证据链
    + 作战记录产出）；缺省表示不统计声明。
    """
    by_preset: dict[str, dict] = defaultdict(
        lambda: {"sessions": set(), "calls": 0, "results": 0, "errors": 0,
                 "policy": Counter(), "supervisor": Counter(),
                 "per_session": Counter(), "repeats": 0})
    # 归属解析：supervisor 记录只有 session、policy 记录只有（尽力而为的）preset，
    # 两边都不完整——先用 call 记录建 session → preset 映射，再给两类记录补归属
    session_preset: dict[str, str] = {}
    for rec in records:
        if isinstance(rec, dict) and rec.get("kind") == "call":
            sid = str(rec.get("session") or "")
            if sid and sid not in session_preset:
                session_preset[sid] = str(rec.get("preset") or "")

    def _preset_of(rec: dict) -> str:
        own = str(rec.get("preset") or "")
        if own:
            return own
        return session_preset.get(str(rec.get("session") or ""), "")

    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = _preset_of(rec)
        if not _match_preset(name, preset):
            continue
        bucket = by_preset[name]
        kind = str(rec.get("kind") or "")
        if kind == "call":
            bucket["calls"] += 1
            session = str(rec.get("session") or "")
            bucket["sessions"].add(session)
            bucket["per_session"][session] += 1
        elif kind == "result":
            bucket["results"] += 1
            if rec.get("isError"):
                bucket["errors"] += 1
        elif kind == "policy":
            bucket["policy"][str(rec.get("decision") or "")] += 1
        elif kind == "supervisor":
            bucket["supervisor"][str(rec.get("decision") or "")] += 1

    # 同指纹重复率：按会话内指纹去重后仍多出来的次数
    seen: dict[tuple[str, str], int] = {}
    for rec in records:
        if not isinstance(rec, dict) or rec.get("kind") != "call":
            continue
        name = _preset_of(rec)
        if not _match_preset(name, preset):
            continue
        key = (str(rec.get("session") or ""), _fingerprint(rec))
        seen[key] = seen.get(key, 0) + 1
    for (session, _fp), count in seen.items():
        if count > 1:
            name = session_preset.get(session, "")
            if _match_preset(name, preset):
                by_preset[name]["repeats"] += count - 1

    stats: dict = {"presets": {}}
    for name in sorted(by_preset):
        bucket = by_preset[name]
        calls = int(bucket["calls"]) or 1
        per_session = [int(v) for v in bucket["per_session"].values()]
        stats["presets"][name or "(未知)"] = {
            "sessions": len(bucket["sessions"]),
            "calls": bucket["calls"],
            "errors": bucket["errors"],
            "policy": dict(bucket["policy"]),
            "supervisor": dict(bucket["supervisor"]),
            "repeats": bucket["repeats"],
            "repeat_rate": round(bucket["repeats"] / calls, 3),
            "calls_p50": _pct(per_session, 0.5),
            "calls_p90": _pct(per_session, 0.9),
            "calls_max": max(per_session) if per_session else 0,
        }
    if claims is not None:
        total = len(claims)
        verified = sum(1 for c in claims if c.get("verified"))
        by_ns: dict[str, Counter] = defaultdict(Counter)
        for claim in claims:
            ns = str(claim.get("namespace") or "(未知)")
            by_ns[ns]["claims"] += 1
            by_ns[ns]["verified"] += 1 if claim.get("verified") else 0
        stats["flags"] = {
            "claims": total,
            "verified": verified,
            "false_claim_rate": (round((total - verified) / total, 3)
                                 if total else None),
            "by_namespace": {k: dict(v) for k, v in sorted(by_ns.items())},
        }
    return stats


def claim_facts(data_dir: str | Path) -> list[dict]:
    """从证据链 + 作战记录收集 flag 声明事实（P2-1 写的那类记录）。

    分区（≈模式）从作战记录的文件位置取——声明记录本身带 `mission`，
    任务按 `memory_namespace` 落盘，这样能回答"哪个方向的题在假声明"。
    """
    from penagent.evidence import EvidenceChain

    root = Path(data_dir)
    chain = EvidenceChain(root / "chain.jsonl")
    facts: list[dict] = []
    for rec in chain.load():
        if rec.kind != "conclusion":
            continue
        content = rec.content or {}
        if content.get("source") != "flag_claim":
            continue
        mid = str(content.get("mission") or "")
        namespace = ""
        if mid:
            found = list((root / "missions").glob(f"*/{mid}.json"))
            if found:
                namespace = found[0].parent.name
        facts.append({"flag": content.get("flag", ""),
                      "verified": bool(content.get("flag_verified")),
                      "namespace": namespace or "(未知)",
                      "mission": mid})
    return facts


def collect(data_dir: str | Path, spool_path: str | Path = "",
            preset: str = "") -> dict:
    """读 spool + 证据链，产出可直接渲染/入库的统计。"""
    root = Path(data_dir)
    spool = Path(spool_path) if spool_path else (root / "dsh-events.jsonl")
    records = read_spool(spool)
    stats = summarize(records, claims=claim_facts(root), preset=preset)
    stats["spool"] = str(spool)
    stats["records"] = len(records)
    return stats


def render(stats: dict) -> str:
    """人读表格（CLI / 评分卡 detail 共用）。"""
    lines = [f"宿主会话守卫统计 · spool={stats.get('spool', '')}"
             f"（{stats.get('records', 0)} 条记录）"]
    header = (f"{'preset':22s}{'会话':>5s}{'调用':>7s}{'失败':>6s}"
              f"{'重复率':>8s}{'p50':>5s}{'p90':>5s}{'max':>5s}   裁决(policy)"
              f" / 守卫(supervisor)")
    lines.append(header)
    for name, row in (stats.get("presets") or {}).items():
        lines.append(
            f"{name:22s}{row['sessions']:5d}{row['calls']:7d}{row['errors']:6d}"
            f"{row['repeat_rate']:8.1%}{row['calls_p50']:5d}{row['calls_p90']:5d}"
            f"{row['calls_max']:5d}   {row['policy']} / {row['supervisor']}")
    flags = stats.get("flags")
    if flags:
        rate = flags.get("false_claim_rate")
        lines.append(
            f"flag 声明: {flags['claims']} 条，判定器接受 {flags['verified']} 条"
            f"，假声明率 {('—' if rate is None else f'{rate:.1%}')}"
            f"；按方向 {flags.get('by_namespace')}")
    if not (stats.get("presets") or {}):
        lines.append("(没有可统计的会话记录——先跑一次 DSH 会话)")
    return "\n".join(lines)
