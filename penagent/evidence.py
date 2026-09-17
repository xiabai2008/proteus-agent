"""证据链：链式哈希不可篡改的作战记录（复用 08 证据链机制）。

每条动作（LLM 决策 + 工具调用 + 输出）固化为证据记录，引用前序哈希，
任何篡改验证即失败——反幻觉校验：结论必须引用真实证据。
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class EvidenceRecord:
    seq: int = 0
    kind: str = ""                 # decision | tool_call | observation | conclusion
    content: dict = field(default_factory=dict)
    timestamp: str = ""
    prev_hash: str = ""
    hash: str = ""

    def canonical(self) -> str:
        return json.dumps({
            "seq": self.seq, "kind": self.kind, "content": self.content,
            "timestamp": self.timestamp, "prev_hash": self.prev_hash,
        }, ensure_ascii=False, sort_keys=True)

    def compute_hash(self) -> str:
        return sha256(self.canonical())

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceRecord":
        r = cls(seq=int(d.get("seq", 0)), kind=d.get("kind", ""),
                content=d.get("content", {}), timestamp=d.get("timestamp", ""),
                prev_hash=d.get("prev_hash", ""), hash=d.get("hash", ""))
        return r


class EvidenceChain:
    """轻量链式哈希证据链（JSONL 存储，追加写）。"""

    def __init__(self, path: str | Path = "data/chain.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def append(self, kind: str, content: dict) -> EvidenceRecord:
        tail = self.tail()
        rec = EvidenceRecord(
            seq=(tail.seq + 1) if tail else 1,
            kind=kind, content=content,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            prev_hash=tail.hash if tail else "",
        )
        rec.hash = rec.compute_hash()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
        return rec

    def tail(self) -> Optional[EvidenceRecord]:
        recs = self.load()
        return recs[-1] if recs else None

    def load(self) -> list[EvidenceRecord]:
        recs = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                recs.append(EvidenceRecord.from_dict(json.loads(line)))
        return recs

    def verify(self) -> dict:
        """校验链完整性：自身哈希 + prev_hash 链。"""
        ok = True
        tampered, broken = [], []
        prev = ""
        for r in self.load():
            if r.hash != r.compute_hash():
                ok = False
                tampered.append(r.seq)
            if r.prev_hash != prev:
                ok = False
                broken.append(r.seq)
            prev = r.compute_hash()
        return {"ok": ok, "length": len(self.load()),
                "tampered": tampered, "broken_links": broken}

    def refs(self, seqs: list[int]) -> list[dict]:
        """按 seq 取证据内容（结论引用校验）。"""
        by_seq = {r.seq: r for r in self.load()}
        return [by_seq[s].content for s in seqs if s in by_seq]

    def valid_refs(self, seqs: list[int]) -> list[int]:
        return [s for s in seqs if s in {r.seq for r in self.load()}]
