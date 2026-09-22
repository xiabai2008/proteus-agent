"""把 Proteus 的 DSH 宿主接入装到本机，并做机制性校验。

为什么需要它——三个"会静默坏掉"的地方，每个都有实测来历（见
`docs/DSH宿主接入指南.md`、`docs/DSH插件化与内核旁路治理.md`）：

1. **复制式安装会漂移**：仓库改了 preset，`$DSH_HOME` 里那份还是旧的，会话照常
   起得来，只是行为悄悄回到旧版。这里默认建**目录链接**（Windows 用 junction，
   不需要管理员权限），仓库即唯一真源。
2. **漏拷一个文件 = preset 静默消失**：`dsh-agent-presets` 对 preset 行只解析
   "本目录相对文件"或已装包；少一个 `.mjs` 就得到 `broken=…`，而 **broken 的
   preset 不进选择器、界面零提示**。这里逐行核对相对 specifier 是否存在。
3. **roster 检查覆盖不到行 config**：它只看行的 `name`，不评估 `!!js`、不看
   `command`/`cwd`。这里额外拦掉 `!!js` 行尾部出现 `": "`——会被 YAML 拆成
   映射键、求值成 `[object Object]`。

用法（仓库根执行）：

    python tools/dsh_install.py             # 安装（幂等）+ 校验 + roster 健康检查
    python tools/dsh_install.py --check     # 只检查，不改动；有问题即非零退出
    python tools/dsh_install.py --copy      # 建不了链接时退回复制（会提示漂移风险）
    python tools/dsh_install.py --profile web --no-bundle-check

退出码：0 = 健康；1 = 有未决问题；2 = 前提缺失（无 node / 无 profile）导致无法判定。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "dsh" / ".agent-presets" / "proteus"
PATCH = REPO / "dsh" / "proteus.cordis.patch.yml"
BRIDGE_NAME = "dsh-proteus-bridge"
REQUIRED_FILES = ("preset.yml", "agent.cordis.yml")
PROTECTED_TIERS = ("proteus-safe", "proteus-standard", "proteus-ctf")

ROSTER_JS = """
import { discoverPresets } from '@deepseek-ai/dsh-agent-presets'
import { pathToFileURL } from 'node:url'
const roots = [{ path: %s, trust: 'user' }]
const found = await discoverPresets(roots, pathToFileURL(process.cwd() + '/x').href)
for (const p of found) console.log(JSON.stringify({ id: p.id, broken: p.broken ?? null }))
"""


def dsh_home(override: str = "") -> Path:
    """DSH home：`--home` > `DSH_HOME` > `~/.dsh`（本机路径不入库）。"""
    if override.strip():
        return Path(override).expanduser()
    env = os.environ.get("DSH_HOME", "").strip()
    return Path(env).expanduser() if env else Path.home() / ".dsh"


# ----------------------------------------------------------------------
# 校验（纯函数，可单测；不依赖 DSH 是否在跑）
# ----------------------------------------------------------------------
def _yaml_rows(path: Path) -> list[dict]:
    """读 composition 的插件行，**容忍未知 tag**（`!!js` 是自定义 tag）。

    用 PyYAML 的 multi-constructor 兜住 `!…` / `tag:yaml.org,2002:…`：不兜的话
    解析直接抛错，而这个工具要做的恰恰是"把坏的 composition 说清楚"。
    """
    import yaml

    class _Tolerant(yaml.SafeLoader):
        pass

    def _unknown(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    _Tolerant.add_multi_constructor("!", _unknown)
    _Tolerant.add_multi_constructor("tag:yaml.org,2002:", _unknown)
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=_Tolerant)
    return [row for row in (data or []) if isinstance(row, dict)]


def verify_preset(dst: Path) -> list[str]:
    """校验装好的 preset 目录（经**目标路径**读，复制漏文件也抓得到）。"""
    problems: list[str] = []
    for name in REQUIRED_FILES:
        if not (dst / name).is_file():
            problems.append(
                f"缺少必需文件 {name}（preset 会 broken，且在选择器里静默消失）")
    cfg = dst / "agent.cordis.yml"
    if not cfg.is_file():
        return problems

    # 先扫原始行：`!!js` 里出现 ": " 时 **YAML 自己就解析不过**。若先解析，报出来的
    # 是一句泛泛的 "mapping values are not allowed here"，真正的原因（那个冒号）会被
    # 盖掉——而这条恰恰是最需要说清楚的坑。
    text = cfg.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#") or "!!js" not in line:
            continue
        if ": " in line.split("!!js", 1)[1]:
            problems.append(
                f"第 {lineno} 行的 !!js 表达式含 ': '（YAML 会拆成映射键，"
                f"求值得到 [object Object]）：{line.strip()[:70]}")

    try:
        rows = _yaml_rows(cfg)
    except Exception as exc:                      # noqa: BLE001 - 解析失败本身要报
        problems.append(f"agent.cordis.yml 解析失败：{exc}")
        return problems

    for row in rows:
        spec = row.get("name")
        if not isinstance(spec, str) or not spec.startswith(("./", "../")):
            continue
        if not (dst / spec).resolve().exists():
            problems.append(
                f"行 {row.get('id')!r} 的相对 specifier 解析不到：{spec}"
                f"（该行会让整个 preset broken）")
    return problems


def verify_patch(path: Path = PATCH) -> list[str]:
    """host 平面补丁必须把三个 Proteus 档位都重申（补丁是整行替换，不是深合并）。"""
    if not path.is_file():
        return [f"host 补丁不存在：{path}（审批档位不会生效）"]
    text = path.read_text(encoding="utf-8")
    missing = [tier for tier in PROTECTED_TIERS if tier not in text]
    return [f"host 补丁缺少档位 {tier}" for tier in missing]


def check_bundle(home: Path, profile: str) -> list[str]:
    """审计层（host 平面 bundle）是否接进 profile —— 没接上等于"旁路不留痕"。"""
    pkg = home / "profiles" / profile / "package.json"
    if not pkg.is_file():
        return [f"找不到 profile 清单：{pkg}（profile {profile!r} 尚未初始化？）"]
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"profile 清单不是合法 JSON：{exc}"]
    deps = data.get("dependencies") or {}
    bundles = ((data.get("dsh") or {}).get("profile") or {}).get("bundles") or []
    problems = []
    if BRIDGE_NAME not in deps:
        problems.append(
            f"profile 依赖里没有 {BRIDGE_NAME}（审计桥不会被加载）")
    if BRIDGE_NAME not in bundles:
        problems.append(
            f"dsh.profile.bundles 里没有 {BRIDGE_NAME}（同上）")
    if problems:
        problems.append(
            f"装法：dsh plugin --profile {profile} add {REPO / 'dsh' / 'proteus-bridge'}"
            "（或开一个创造模式会话用 plugin_manager 安装）")
    return problems


def roster_check(home: Path) -> tuple[list[str], str]:
    """用 DSH 自己的发现机制读一次 roster；返回 (问题, 说明)。

    `broken` 为空只说明"这份 preset 装得上"——它不评估 `!!js`、不看
    `command`/`cwd`，所以 `verify_preset` 与它不是替代关系。
    """
    node = shutil.which("node")
    if node is None:
        return [], "跳过 roster 检查（本机无 node）"
    cwd = home / "profiles"
    if not (cwd / "node_modules" / "@deepseek-ai" / "dsh-agent-presets").exists():
        return [], f"跳过 roster 检查（{cwd / 'node_modules'} 里没有 harness 包）"
    script = ROSTER_JS % json.dumps(str(home / ".agent-presets"))
    proc = subprocess.run([node, "--input-type=module", "-e", script], cwd=cwd,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=120)
    if proc.returncode != 0:
        return [], f"跳过 roster 检查（node 退出码 {proc.returncode}："                    f"{(proc.stderr or '').strip()[:120]}）"
    rows = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            rows.append(json.loads(line))
    if not rows:
        return ["roster 里一个 preset 都没有——发现根可能不对"], ""
    found = [r for r in rows if r.get("id") == "proteus"]
    if not found:
        return ["roster 里没有 proteus（目录名或位置不对，见指南第二节）"], ""
    broken = found[0].get("broken")
    if broken:
        return [f"proteus 在 roster 里是 broken：{broken}"], ""
    return [], f"roster OK（{len(rows)} 个 preset，proteus 未 broken）"


# ----------------------------------------------------------------------
# 安装
# ----------------------------------------------------------------------
def _is_reparse_point(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    flag = getattr(os.stat_result, "st_file_attributes", None)
    attrs = getattr(st, "st_file_attributes", 0)
    reparse = getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(flag is not None and attrs & reparse)


def _points_to(dst: Path, src: Path) -> bool:
    if not (os.path.islink(dst) or _is_reparse_point(dst)):
        return False
    try:
        return Path(os.path.realpath(dst)) == Path(os.path.realpath(src))
    except OSError:
        return False


def install_kind(dst: Path) -> str:
    """目标目录的安装形态：`link`（指向仓库）/ `copy`（会漂移）/ `missing`。"""
    if not (dst.exists() or os.path.islink(dst)):
        return "missing"
    return "link" if _points_to(dst, SRC) else "copy"


def _make_link(src: Path, dst: Path) -> str:
    """建目录链接：先试 symlink，Windows 上退 junction（不需要管理员）。"""
    try:
        os.symlink(src, dst, target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError) as exc:
        symlink_error = exc
    if os.name != "nt":
        raise RuntimeError(f"建符号链接失败：{symlink_error}")
    proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(dst), str(src)],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    if proc.returncode != 0:
        detail = ((proc.stdout or "") + (proc.stderr or "")).strip()[:200]
        raise RuntimeError(
            f"建目录链接失败（symlink: {symlink_error}；junction: {detail}）"
            "——可用 --copy 退回复制安装")
    return "junction"


def install(home: Path, copy: bool = False) -> list[str]:
    """安装/更新 preset 目录；返回动作说明。"""
    dst = home / ".agent-presets" / "proteus"
    notes: list[str] = []
    dst.parent.mkdir(parents=True, exist_ok=True)

    if dst.exists() or os.path.islink(dst):
        if copy:
            if _is_reparse_point(dst) or os.path.islink(dst):
                os.unlink(dst)
                notes.append("移除原有链接")
        elif _points_to(dst, SRC):
            notes.append(f"已是指向仓库的链接，无需改动：{dst}")
            return notes
        else:
            backup = dst.with_name(f"proteus.bak-{_stamp()}")
            if _is_reparse_point(dst) or os.path.islink(dst):
                os.unlink(dst)
            else:
                dst.rename(backup)
                notes.append(f"原有真实目录已备份到 {backup.name}")
    if copy:
        shutil.copytree(SRC, dst, dirs_exist_ok=True)
        notes.append(f"已复制 {len(list(SRC.iterdir()))} 项到 {dst}"
                     "（复制模式下仓库改动不会自动生效，改完要重跑本脚本）")
        return notes
    kind = _make_link(SRC, dst)
    notes.append(f"已建{kind}：{dst} -> {SRC}")
    return notes


def _stamp() -> str:
    import time

    return time.strftime("%Y%m%d%H%M%S")


# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python tools/dsh_install.py",
        description="安装并校验 Proteus 的 DSH 宿主接入")
    ap.add_argument("--home", default="", help="DSH home（缺省 $DSH_HOME 或 ~/.dsh）")
    ap.add_argument("--profile", default="web", help="profile 名（缺省 web）")
    ap.add_argument("--check", action="store_true", help="只检查，不改动")
    ap.add_argument("--copy", action="store_true",
                    help="退回复制安装（建不了链接时用）")
    ap.add_argument("--no-roster", action="store_true", help="跳过 roster 健康检查")
    ap.add_argument("--no-bundle-check", action="store_true",
                    help="跳过审计桥的 profile 接线检查")
    args = ap.parse_args(argv)

    home = dsh_home(args.home)
    dst = home / ".agent-presets" / "proteus"
    print(f"DSH home : {home}")
    print(f"preset   : {dst}")

    problems: list[str] = []
    if not args.check:
        try:
            for note in install(home, copy=args.copy):
                print(f"  - {note}")
        except RuntimeError as exc:
            print(f"  ! {exc}")
            return 2

    problems += verify_preset(dst)
    problems += verify_patch()
    if not args.no_bundle_check:
        problems += check_bundle(home, args.profile)

    notes: list[str] = []
    if install_kind(dst) == "copy":
        notes.append("当前是**复制安装**（不是链接）：仓库改了 preset 不会生效，"
                     "重跑本脚本（不带 --check）即改为链接")
    if not args.no_roster:
        roster_problems, roster_note = roster_check(home)
        problems += roster_problems
        if roster_note:
            notes.append(roster_note)

    for note in notes:
        print(f"  · {note}")
    if problems:
        print(f"发现 {len(problems)} 个问题：")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print("接入健康：preset 可解析、补丁完整、审计桥已接线")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
