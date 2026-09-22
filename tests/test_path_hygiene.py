"""硬规则 7 的机制性把关：入库文件不得含本机绝对路径。

为什么要用例兜：这类泄漏靠"记得检查"守不住——2026-09-21 那次清洗只覆盖
docs/ 与根文档，此后新增的文档、工具脚本、测试里又漏进了真机路径（含用户
名与工具目录），而**没有任何东西会报错**。所以判据落在 pytest 每次都扫一遍。

写法要点：本机路径从运行时解析（`envcfg.local_needles()`），不写死在用例里
——写死就等于让用例自己再泄一份。未配置 `.env` 的机器仍会检查仓库根与
主目录，用例照样有效（不 skip 成空转）。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from penagent import envcfg  # noqa: E402


def _tracked_files() -> list[Path]:
    """`git ls-files -z` 列出的入库文件（无 git 则 skip，不误报）。

    `-z` 不是可选项：默认输出会把非 ASCII 路径转义成八进制引号形式，中文名
    文档会被静默漏扫——而"漏扫"在这里等于"用例假绿"。
    """
    try:
        proc = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
    except OSError as exc:                       # git 不在 PATH
        pytest.skip(f"git 不可用: {exc}")
    if proc.returncode != 0:
        pytest.skip("不在 git 工作树内，跳过入库文件扫描")
    return [ROOT / name for name in proc.stdout.split("\0") if name.strip()]


def test_no_local_absolute_paths_in_tracked_files():
    """任何入库文件都不得出现本机路径（仓库根 / 主目录 / .env 里的 PENTEST_*）。"""
    needles = envcfg.local_needles()
    offenders: list[str] = []
    for path in _tracked_files():
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue                            # 二进制（demo.gif 等）不扫
        rel = path.relative_to(ROOT)
        for value, placeholder in needles:
            if envcfg.local_path_pattern(value).search(text):
                offenders.append(f"{rel}: 含本机路径 {value!r}"
                                 f"（应写作 {placeholder}）")
    assert not offenders, (
        "入库文件含本机路径（硬规则 7）。就地清洗："
        "python tools/scrub_paths.py\n  " + "\n  ".join(offenders))


def test_scrub_helper_detects_and_replaces():
    """清洗机制本身可用：检出 -> 替换；分隔符与大小写不敏感。

    这条防的是"用例绿但工具废"——`local_path_pattern` 若只按原样匹配，
    pip 输出那种全小写、且分隔符翻倍的形式就永远漏过。

    注：本用例自己也在扫描范围内（提交后即进 `git ls-files`）——所以这段
    docstring 同样不能写真实路径示例，只能描述形态。
    """
    value, placeholder = envcfg.local_needles()[0]
    text = f"prefix {value} suffix"
    # 断言"包含"而非"等于"：needles 之间有父子关系（工作区根是 07 靶场根的
    # 父路径），命中子路径时父路径也会命中——这是预期的，不是重复
    assert value in envcfg.find_local_paths(text)
    cleaned = envcfg.scrub_local_paths(text)
    assert value not in cleaned
    assert placeholder in cleaned
    assert cleaned.startswith("prefix ") and cleaned.endswith(" suffix")

    # 分隔符互换 / 大小写变化都必须仍被认出
    flipped_sep = (value.replace("\\", "/") if "\\" in value
                   else value.replace("/", "\\"))
    assert envcfg.local_path_pattern(value).search(flipped_sep)
    flipped_case = value.lower() if value != value.lower() else value.upper()
    assert envcfg.local_path_pattern(value).search(flipped_case)
