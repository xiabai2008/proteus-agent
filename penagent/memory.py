"""作战记录与经验库：自我进化的记忆底座。

- 作战记录（missions/<namespace>/）：每轮任务的完整轨迹（目标/决策/工具/结果/反思）
- 经验库（skills/<namespace>/）：LLM 反思后沉淀的可复用技能（带证据引用）

按 memory_namespace 分区：每个模式读写自己的记忆域，模式间互不串库
（渗透沉淀的技能不会被 CTF 任务检索到，反之亦然）。
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_NAMESPACE = "default"
_NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_namespace(namespace: str) -> str:
    """校验分区名：只允许字母数字与 . _ -，拒绝路径穿越。"""
    name = (namespace or "").strip() or DEFAULT_NAMESPACE
    if name in (".", "..") or not _NAMESPACE_PATTERN.match(name):
        raise ValueError(f"非法 memory_namespace: {namespace!r}")
    return name


@dataclass
class Skill:
    """LLM 提炼的可复用技能（带证据引用，无证据不进库）。"""
    id: str = ""
    title: str = ""
    target_fingerprint: str = ""      # 适用目标特征（如 "python web / flask"）
    steps: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    evidence_refs: list[int] = field(default_factory=list)
    evidence_text: str = ""           # 工具产出的证据文本（JSON/指纹等）
    category: str = ""                # 漏洞方向标签（sqli/xss/ssrf/...）
    success_rate: float = 0.0
    successes: int = 0                # 复用成功次数
    attempts: int = 0                 # 复用尝试次数
    exposure: Optional[int] = None    # 对抗暴露：真实告警类别数（低=隐蔽）
    source_mission: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict) -> "Skill":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def record_outcome(self, success: bool) -> None:
        """技能复用结果回写（成功/失败计数与成功率）。"""
        self.attempts += 1
        if success:
            self.successes += 1
        self.success_rate = (self.successes / self.attempts
                             if self.attempts else 0.0)


class Memory:
    """作战记录 + 经验库（按 namespace 分区）。"""

    def __init__(self, root: str | Path = "data",
                 namespace: str = DEFAULT_NAMESPACE) -> None:
        self.root = Path(root)
        self.namespace = _safe_namespace(namespace)
        self.missions_dir = self.root / "missions" / self.namespace
        self.skills_dir = self.root / "skills" / self.namespace
        self.missions_dir.mkdir(parents=True, exist_ok=True)
        self.skills_dir.mkdir(parents=True, exist_ok=True)

    def for_namespace(self, namespace: str) -> "Memory":
        """返回同一根目录下、指定分区的 Memory（模式切换记忆域用）。"""
        return Memory(self.root, namespace=namespace)

    def namespaces(self) -> list[str]:
        """已存在的分区名（含当前分区）。"""
        found = set()
        for kind in ("missions", "skills"):
            base = self.root / kind
            if base.is_dir():
                found.update(p.name for p in base.iterdir() if p.is_dir())
        return sorted(found)

    @classmethod
    def locate_mission(cls, root: str | Path,
                       mission_id: str) -> Optional[tuple[str, dict]]:
        """跨分区查找任务：返回 `(namespace, 记录)`，找不到返回 None。

        为什么要跨分区（2026-09-24 真机实测）：任务按 `memory_namespace` 分区
        落盘，而 `Memory(root)` 默认只看 `default` 分区。`python -m penagent
        reflect` 与 MCP 的 `pentest_reflect` 此前都按 `Memory(data)` 找任务，
        于是**任何模式下跑出来的任务都找不到**——DSH 会话里必然如此（三个 preset
        的默认模式都不是 default），技能沉淀闭环直接断掉，连带
        `/proteus-skills` 导出目录永远是空的。

        视图侧早已按分区扫（`report._all_missions`），这里把同一口径补到"读单条"。

        `mission_id` 只允许普通 id（拒绝路径分隔符与 `..`）——它可能来自模型或
        命令行输入，不做校验就等于把任务读取变成任意文件读取。
        """
        if (not mission_id or "/" in mission_id or "\\" in mission_id
                or ".." in mission_id):
            return None
        base = cls(root)
        for namespace in base.namespaces() or [base.namespace]:
            path = base.root / "missions" / namespace / f"{mission_id}.json"
            if not path.is_file():
                continue
            try:
                return namespace, json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError(f"任务文件损坏：{path}（{exc}）") from exc
        return None

    # ------------------------------------------------------------------
    # 作战记录
    def new_mission(self, target: str, objective: str) -> str:
        mission_id = str(uuid.uuid4())[:8]
        record = {
            "id": mission_id, "target": target, "objective": objective,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at": "", "steps": [], "reflection": "",
            "outcome": "running",
        }
        self._save_mission(record)
        return mission_id

    def add_step(self, mission_id: str, step: dict) -> None:
        rec = self._load_mission(mission_id)
        rec["steps"].append(step)
        self._save_mission(rec)

    def finish(self, mission_id: str, outcome: str,
               reflection: str = "",
               evidence_refs: Optional[list] = None) -> None:
        rec = self._load_mission(mission_id)
        rec["outcome"] = outcome
        rec["reflection"] = reflection
        rec["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if evidence_refs is not None:
            # 结论引用了哪些证据——层级视图与评测都要它；此前只在链上，
            # 作战记录里查不到（P2-3 补齐）
            rec["evidence_refs"] = [int(x) for x in evidence_refs]
        self._save_mission(rec)

    def get_mission(self, mission_id: str) -> dict:
        return self._load_mission(mission_id)

    def set_target(self, mission_id: str, target: str) -> None:
        """补任务目标（仅当为空时写）：自动绑定任务的 target 取自首个
        底层调用的参数，而首调可能是 `replay_request` 这类不带目标信息的
        工具——后续调用提取到目标时回填，宁晚不缺。"""
        rec = self._load_mission(mission_id)
        if target and not rec.get("target"):
            rec["target"] = target
            self._save_mission(rec)

    def list_missions(self) -> list[dict]:
        missions = []
        for p in sorted(self.missions_dir.glob("*.json")):
            missions.append(json.loads(p.read_text(encoding="utf-8")))
        return missions

    def _load_mission(self, mission_id: str) -> dict:
        return json.loads(
            (self.missions_dir / f"{mission_id}.json").read_text(
                encoding="utf-8"))

    def _save_mission(self, rec: dict) -> None:
        (self.missions_dir / f"{rec['id']}.json").write_text(
            json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # 经验库（技能）
    def add_skill(self, skill: Skill) -> Skill:
        skill.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._save_skill(skill)
        return skill

    def update_skill(self, skill: Skill) -> None:
        self._save_skill(skill)

    def _save_skill(self, skill: Skill) -> None:
        (self.skills_dir / f"{skill.id}.json").write_text(
            json.dumps(skill.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8")

    def list_skills(self, sort_by_rate: bool = False,
                    sort_by_stealth: bool = False,
                    category: str = "") -> list[Skill]:
        skills = []
        for p in sorted(self.skills_dir.glob("*.json")):
            s = Skill.from_dict(
                json.loads(p.read_text(encoding="utf-8")))
            if category and s.category != category:
                continue
            skills.append(s)
        if sort_by_stealth:
            # 隐蔽优先：暴露低（None 视为未知=最保守放最后）且成功率高的在前
            skills.sort(
                key=lambda s: (s.exposure if s.exposure is not None
                               else 10 ** 9, -s.success_rate))
        elif sort_by_rate:
            skills.sort(key=lambda s: s.success_rate, reverse=True)
        return skills

    def find_skills(self, fingerprint: str) -> list[Skill]:
        """按目标指纹匹配技能（关键词交集，兼容中英文自然语言指纹）。

        LLM 提炼的技能指纹是自然语言描述，自动指纹是结构化短语——
        用关键词共现匹配（忽略纯数字 token，如 IP 段）。
        """
        import re

        def words(text: str) -> set[str]:
            return {w for w in re.findall(r"[a-z0-9]+", text.lower())
                    if not w.isdigit()}

        fp_words = words(fingerprint)
        hits = []
        for s in self.list_skills():
            if fp_words & words(s.target_fingerprint):
                hits.append(s)
        return hits

    def recent_skills(self, limit: int = 5) -> list[Skill]:
        return self.list_skills()[-limit:]
