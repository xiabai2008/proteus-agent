"""内核经验库 → DSH 技能目录导出（F4 技能融合）。

一份实现两个入口：
  - CLI：python -m penagent skills --export [--out DIR] [--namespace X]
  - 命令：/proteus-skills（DSH 命令插件 spawn 本 CLI）

输出：扁平 Markdown 技能（`<namespace>-<id8>.md` + YAML frontmatter），
与 dsh-skill-filesystem 的"flat Markdown skills"发现形态对齐——preset 里
把 customSkillDirs 指到导出目录即可，DSH 侧零代码。
幂等：同名覆盖（slug 由 namespace+id 派生，重导不改名）。
"""
from __future__ import annotations

import json
from pathlib import Path

from penagent.memory import Skill


def _slug(namespace: str, skill_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in skill_id)
    return f"{namespace}-{safe[:8]}"


def _fmt_rate(d: dict) -> str:
    attempts = int(d.get("attempts") or 0)
    successes = int(d.get("successes") or 0)
    rate = float(d.get("success_rate") or 0)
    if attempts <= 0:
        return "未复用"
    return f"{rate:.0%}（{successes}/{attempts}）"


def _quote_yaml(text: str) -> str:
    """frontmatter 单行值：压平换行并转义双引号。"""
    flat = " ".join(str(text).split())
    return '"' + flat.replace('"', "'") + '"'


def _to_markdown(namespace: str, d: dict) -> str:
    skill = Skill.from_dict(d)
    category = d.get("category") or "通用"
    fingerprint = d.get("target_fingerprint") or "通用"
    title = d.get("title") or skill.id or "未命名技能"
    description = (f"[Proteus 技能|{category}] {title} · "
                   f"成功率 {_fmt_rate(d)} · 适用 {fingerprint}")

    lines = [
        "---",
        f"name: {_quote_yaml('proteus-' + skill.id or title)}",
        f"description: {_quote_yaml(description)}",
        f"whenToUse: {_quote_yaml('目标特征匹配 ' + fingerprint + ' 或涉及 ' + category + ' 方向时')}",
        "---",
        "",
        f"# {title}",
        "",
        f"- 来源: Proteus 内核经验库（分区 {namespace} · id {d.get('id', '?')}）",
        f"- 成功率: {_fmt_rate(d)}"
        + (f" · 对抗暴露: {d.get('exposure')}" if d.get("exposure") is not None else ""),
        f"- 创建: {d.get('created_at', '?')} · 源任务: {d.get('source_mission', '?')}",
        "",
    ]
    steps = d.get("steps") or []
    if steps:
        lines += ["## 步骤", ""]
        lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
        lines.append("")
    tools = d.get("tools") or []
    if tools:
        lines += ["## 工具", ""]
        lines += [f"- {t}" for t in tools]
        lines.append("")
    refs = d.get("evidence_refs") or []
    evidence_text = str(d.get("evidence_text") or "").strip()
    if refs or evidence_text:
        lines += ["## 证据", ""]
        if refs:
            lines.append(f"- 证据链引用序号: {', '.join(map(str, refs))}")
        if evidence_text:
            lines.append("")
            lines += ["```", evidence_text[:1500], "```"]
    return "\n".join(lines)


def export_skills(data_dir: str | Path, out_dir: str | Path,
                  namespace: str = "") -> dict:
    """导出全部（或指定分区的）技能为 DSH 扁平 Markdown 技能。幂等覆盖。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    count, files = 0, []
    for skill_file in sorted(Path(data_dir).glob("skills/*/*.json")):
        ns = skill_file.parent.name
        if namespace and ns != namespace:
            continue
        try:
            d = json.loads(skill_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # 损坏条目跳过，不阻塞整体导出
        slug = _slug(ns, str(d.get("id") or skill_file.stem))
        md = _to_markdown(ns, d)
        (out / f"{slug}.md").write_text(md, encoding="utf-8")
        files.append(slug)
        count += 1
    return {"count": count, "files": files, "out_dir": str(out)}
