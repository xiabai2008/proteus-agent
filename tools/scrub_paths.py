"""公开前路径清洗：把入库文件里的本机路径替换为占位符。

本机路径一律在运行时解析，**不写进源码**（硬规则 7；写死就意味着清洗工具
自己先泄一次）。解析与匹配逻辑在 `penagent/envcfg.py` 的 `local_needles()`
/`scrub_local_paths()`，与回归用例共用同一份实现。

用法（在仓库根执行）：

    python tools/scrub_paths.py            # 就地清洗，打印改动文件
    python tools/scrub_paths.py --check    # 只检查；有残留则退出码 1
    python tools/scrub_paths.py --history  # 打印 git filter-repo 的替换表
                                           # （历史改写用，输出**不要**入库）

只处理 `git ls-files` 列出的入库文件，不碰 data/ 等本地运行产物。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from penagent import envcfg  # noqa: E402

# 只扫文本类文件；二进制（demo.gif 等）跳过
TEXT_SUFFIXES = {".md", ".html", ".htm", ".txt", ".py", ".json", ".yml",
                 ".yaml", ".cmd", ".bat", ".ps1", ".sh", ".ini", ".toml",
                 ".cfg", ".svg", ".js", ".mjs", ".cjs", ".ts"}


def tracked_files() -> list[Path]:
    """`git ls-files -z` 的入库文件（无 git 时返回空表，调用方据此报错）。

    必须用 `-z`：默认输出会把非 ASCII 路径做八进制引号转义
    （`"docs/\344\277..."`），文件名从此对不上——**中文名文档会被静默跳过**，
    正是这个 bug 让首轮 `--check` 漏报了 docs/ 下的两处路径。
    """
    proc = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    if proc.returncode != 0:
        return []
    return [ROOT / name for name in proc.stdout.split("\0") if name.strip()]


def history_table() -> list[str]:
    """git filter-repo 用的 `旧==>新` 行（两种分隔符各一条）。"""
    lines: list[str] = []
    for value, placeholder in envcfg.local_needles():
        lines.append(f"{value}==>{placeholder}")
        alt = (value.replace("/", "\\") if "/" in value
               else value.replace("\\", "/"))
        if alt != value:
            lines.append(f"{alt}==>{placeholder}")
    return lines


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    pairs = envcfg.local_needles()

    if "--history" in args:
        print("\n".join(history_table()))
        return 0

    check = "--check" in args
    files = tracked_files()
    if not files:
        print("git ls-files 不可用（请在仓库根、且装了 git 的环境执行）")
        return 2

    hits: list[tuple[Path, list[str]]] = []
    for path in files:
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found = envcfg.find_local_paths(original)
        if not found:
            continue
        hits.append((path, found))
        if not check:
            path.write_text(envcfg.scrub_local_paths(original),
                            encoding="utf-8")

    if check:
        if hits:
            print(f"发现 {len(hits)} 个入库文件含本机路径：")
            for path, found in hits:
                rel = path.relative_to(ROOT)
                print(f"  {rel}: {', '.join(found)}")
            return 1
        print("干净：入库文件不含本机路径")
        return 0

    print(f"已清洗 {len(hits)} 个文件（占位符共 {len(pairs)} 条）")
    for path, _ in hits:
        print(" -", path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
