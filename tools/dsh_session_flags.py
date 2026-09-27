# -*- coding: utf-8 -*-
"""从 DSH 会话存档里取"最终 flag"——三臂对照里 **A 臂（无内核）** 的测量工具。

为什么需要它（路线图 P2-3）：三臂对照要算**假声明率**（声称解出但判定器不接受）。
B/C 两臂的声明走内核（`flag_claim` → 证据链 → `python -m penagent guards`），
而 A 臂（纯 DSH 标准模式、不挂内核工具）**只在会话里说了个 flag**，内核侧什么都
没有。这个脚本把 A 臂的读数补上：读会话存档（`~/.dsh/sessions/<ws>/<session>/
session.v4.jsonl.zstd`），抽出最终回复里的 flag；可选带一条**按 argv 列表给**的
校验命令（`{flag}` 占位符在单个参数内替换，不经 shell 解析）。

用法（仓库根执行）：

    python tools/dsh_session_flags.py --list [--ws 羊城杯]
    python tools/dsh_session_flags.py <session-id>
    python tools/dsh_session_flags.py <session-id> --check <echo> --check ...

依赖：`zstandard`（读 DSH 存档；未安装时本脚本明确报错退出——可选依赖，
与 torch 同定位）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

#: flag 候选（与 CTF 模式默认判定正则同形）
FLAG_RE = re.compile(r"(?i)(flag|ctf)\{[^}]{1,200}\}")

DEFAULT_SESSIONS = Path(os.path.expanduser("~")) / ".dsh" / "sessions"


def read_archive(path: Path) -> list[dict]:
    """读会话存档（zstd 压缩的 JSONL；容错解析，坏行跳过）。"""
    try:
        import zstandard as zstd
    except ImportError:                       # pragma: no cover - 环境相关
        raise SystemExit("需要 zstandard 读 DSH 会话存档：pip install zstandard")
    with open(path, "rb") as fh:
        text = zstd.ZstdDecompressor().stream_reader(fh).read().decode(
            "utf-8", "replace")
    rows: list[dict] = []
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        while index < len(text) and text[index] in " \r\n\t":
            index += 1
        if index >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, index)
        except ValueError:
            break
        rows.append(obj)
        index = end
    return rows


def _record_text(record: dict) -> str:
    data = record.get("data") or {}
    for key in ("message", "content", "text"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, dict):
            inner = value.get("content")
            if isinstance(inner, str):
                return inner
            if isinstance(inner, list):
                return json.dumps(inner, ensure_ascii=False)
    return ""


def final_flags(rows: list[dict], limit: int = 6) -> dict:
    """抽最终回复里的 flag：返回 `{"final": [...], "all": [...]}`。

    `final` 取**最后一条 assistant 消息**里的 flag（那才是"它报的答案"），
    `all` 是全存档出现过的（对照"过程里试过哪些"）。
    """
    final_text, all_text = "", ""
    for record in rows:
        kind = record.get("type")
        if kind not in ("assistant/message", "message", "system/message"):
            continue
        role = (record.get("data") or {}).get("role") or ""
        if role not in ("", "assistant"):
            continue
        text = _record_text(record)
        if text:
            final_text = text
        all_text += text + "\n"

    def _unique(text: str) -> list[str]:
        out: list[str] = []
        for match in FLAG_RE.finditer(text):
            if match.group(0) not in out:
                out.append(match.group(0))
        return out[:limit]

    return {"final": _unique(final_text), "all": _unique(all_text)}


def find_session(session_id: str, root: Path) -> Path | None:
    """按会话号找存档（`dad79464-...` 与 `session-dad79464-...` 两种写法都收）。"""
    wanted = str(session_id).strip()
    candidates = [wanted]
    if not wanted.startswith("session-"):
        candidates.append(f"session-{wanted}")
    for name in candidates:
        # 真实布局是 <root>/<工作区目录>/<会话目录>/...；也容忍直接一层
        for pattern in (f"*/{name}/session.v4.jsonl.zstd",
                        f"{name}/session.v4.jsonl.zstd"):
            for path in root.glob(pattern):
                return path
    return None


def list_sessions(root: Path) -> list[tuple[str, str]]:
    return [(path.parent.name, path.parent.parent.name)
            for path in sorted(root.glob("*/session-*/session.v4.jsonl.zstd"))]


def check_flag(flag: str, argv: list[str]) -> tuple[str, str]:
    """按 argv 列表跑校验命令（`{flag}` 在单个参数内替换；不经 shell）。"""
    command = [part.replace("{flag}", flag) for part in argv]
    try:
        done = subprocess.run(command, shell=False, capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              cwd=str(REPO), timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        return "ERROR", str(exc)[:160]
    lines = (done.stdout or done.stderr or "").strip().splitlines()
    return ("ACCEPT" if done.returncode == 0 else "REJECT"), \
        (lines[-1][:160] if lines else "")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="取 DSH 会话里的 flag（A 臂测量）")
    ap.add_argument("session", nargs="?", default="", help="会话 id（session-...）")
    ap.add_argument("--root", default=str(DEFAULT_SESSIONS),
                    help="会话存档根（缺省 ~/.dsh/sessions）")
    ap.add_argument("--ws", default="", help="只看该工作区目录（子串匹配）")
    ap.add_argument("--list", action="store_true", help="列出可选会话")
    ap.add_argument("--check", nargs="+", default=None, metavar="ARGV",
                    help="校验命令（argv 列表，末尾；保留字 {flag} 会被替换）")
    args = ap.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"会话存档目录不存在: {root}")
        return 1
    if args.list or not args.session:
        rows = list_sessions(root)
        if args.ws:
            rows = [row for row in rows if args.ws in row[1]]
        for session, workspace in rows[-30:]:
            print(f"{session}  [{workspace}]")
        return 0
    path = find_session(args.session, root)
    if path is None:
        print(f"没找到会话 {args.session}（--list 看可选项）")
        return 1
    rows = read_archive(path)
    flags = final_flags(rows)
    print(f"会话 {args.session}（{len(rows)} 条记录）")
    print(f"  最终回复里的 flag  : {flags['final'] or '(无)'}")
    print(f"  过程里出现过的 flag: {flags['all'] or '(无)'}")
    if args.check:
        for flag in flags["final"]:
            verdict, tail = check_flag(flag, args.check)
            print(f"  {verdict:6s} {flag}")
            if tail:
                print(f"         {tail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
