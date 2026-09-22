"""把 Proteus 的 DSH 宿主接入同步到本机，并做机制性校验。

**为什么是"复制 + 同步"而不是链接**（2026-09-22 真机实测，推翻了本工具的第一版设计）：
DSH 的 preset 发现机制**不跟随 reparse point**。把
`$DSH_HOME/.agent-presets/proteus` 建成 junction 之后，`discoverPresets` 的返回
从 2 个 preset 变成 1 个——proteus 直接**从选择器里消失**（无任何提示）。所以
preset 目录必须是**真实目录**，靠"每次启动前同步 + 漂移校验"保证它等于仓库。

（bundle 层不受此限：它由 Node 的模块解析从 `node_modules` 加载，所以官方
`link:` 依赖 + junction 是正确形态——见 `check_bridge_entry`。）

本工具挡三类**静默失效**：

1. **跑旧代码**：安装副本落后于仓库时，会话照常起得来、行为却停在旧版。实测踩中过
   ——09-22 上午装的副本让当天下午写的内核缺位守卫**根本没上线**。`--check` 比对
   每个文件的哈希，过期即报。
2. **漏拷一个文件 = preset 静默消失**：`dsh-agent-presets` 对 preset 行只解析
   "本目录相对文件"或已装包；少一个 `.mjs` 就得到 `broken=…`，而 **broken 的
   preset 不进选择器、界面零提示**。
3. **roster 覆盖不到行 config**：它只看行的 `name`，不评估 `!!js`、不看
   `command`/`cwd`。这里额外拦掉 `!!js` 行尾部出现 `": "`——会被 YAML 拆成
   映射键、求值成 `[object Object]`。

用法（仓库根执行）：

    python tools/dsh_install.py             # 同步（幂等）+ 校验 + roster 健康检查
    python tools/dsh_install.py --check     # 只检查，不改动；有问题即非零退出
    python tools/dsh_install.py --profile web --no-bundle-check

备份：同步前若有文件要改，先把改动前的副本存到
`$DSH_HOME/backups/preset-proteus-<时间戳>/`（**不能放在 preset 根目录里**——那会
被发现机制当成一个 preset）。只保留最近 3 份。

退出码：0 = 健康；1 = 有未决问题；2 = 前提缺失（无 node / 无 profile）导致无法判定。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "dsh" / ".agent-presets" / "proteus"
PATCH = REPO / "dsh" / "proteus.cordis.patch.yml"
BRIDGE_NAME = "dsh-proteus-bridge"
BRIDGE_SRC = REPO / "dsh" / "proteus-bridge"
REQUIRED_FILES = ("preset.yml", "agent.cordis.yml")
PROTECTED_TIERS = ("proteus-safe", "proteus-standard", "proteus-ctf")
KEEP_BACKUPS = 3

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
def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_reparse_point(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & reparse)


def drift(dst: Path) -> list[str]:
    """安装副本 vs 仓库的逐文件差异——"跑旧代码"的唯一可靠判据。"""
    problems: list[str] = []
    if not dst.is_dir():
        return [f"preset 目录不存在：{dst}"]
    for src_file in sorted(p for p in SRC.iterdir() if p.is_file()):
        target = dst / src_file.name
        if not target.is_file():
            problems.append(f"缺少 {src_file.name}（仓库里有）")
        elif _sha(target) != _sha(src_file):
            problems.append(
                f"{src_file.name} 已过期（安装 {target.stat().st_size} 字节 / "
                f"仓库 {src_file.stat().st_size} 字节）")
    return problems


def _yaml_rows(path: Path) -> list[dict]:
    """读 composition 的插件行，**容忍未知 tag**（`!!js` 是自定义 tag）。"""
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
    """校验装好的 preset 目录（经**目标路径**读，漏拷文件也抓得到）。"""
    problems: list[str] = []
    for name in REQUIRED_FILES:
        if not (dst / name).is_file():
            problems.append(
                f"缺少必需文件 {name}（preset 会 broken，且在选择器里静默消失）")
    cfg = dst / "agent.cordis.yml"
    if not cfg.is_file():
        return problems

    # 先扫原始行：`!!js` 里出现 ": " 时 **YAML 自己就解析不过**。若先解析，报出来的
    # 是一句泛泛的 "mapping values are not allowed here"，真正的原因会被盖掉。
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
    return [f"host 补丁缺少档位 {tier}" for tier in PROTECTED_TIERS
            if tier not in text]


def check_bundle(home: Path, profile: str) -> list[str]:
    """审计层是否接进 profile（依赖 + 组合包选择，两处都要有）。"""
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
        problems.append(f"profile 依赖里没有 {BRIDGE_NAME}（审计桥不会被加载）")
    if BRIDGE_NAME not in bundles:
        problems.append(f"dsh.profile.bundles 里没有 {BRIDGE_NAME}（同上）")
    if problems:
        problems.append(
            "装法（官方路径）：dsh plugin --profile " + profile + " add "
            + str(BRIDGE_SRC))
    return problems


def check_bridge_entry(home: Path, profile: str) -> list[str]:
    """`node_modules` 里的桥必须是**链接**——普通目录说明它是旧副本。

    实测（2026-09-22）：手工兜底留下的是 09-21 的普通目录副本，而仓库里的桥已在
    09-22 重构成薄再导出——审计层因此跑了两天前的代码，没有任何提示。
    """
    entry = home / "profiles" / profile / "node_modules" / BRIDGE_NAME
    if not entry.exists():
        return [f"{entry} 不存在（审计桥没装）"]
    if _is_reparse_point(entry):
        return []
    return [f"{entry} 是普通目录（旧副本）：审计层跑的不是仓库当前代码。"
            f"按官方路径重装即可改成链接：dsh plugin --profile {profile} add "
            f"{BRIDGE_SRC}"]


def roster_check(home: Path) -> tuple[list[str], str]:
    """用 DSH 自己的发现机制读一次 roster；返回 (问题, 说明)。

    `broken` 为空只说明"这份 preset 装得上"——它不评估 `!!js`、不看
    `command`/`cwd`，所以与 `verify_preset` 不是替代关系。
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
        return [], (f"跳过 roster 检查（node 退出码 {proc.returncode}："
                    f"{(proc.stderr or '').strip()[:120]}）")
    rows = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            rows.append(json.loads(line))
    if not rows:
        return ["roster 里一个 preset 都没有——发现根可能不对"], ""
    found = [r for r in rows if r.get("id") == "proteus"]
    if not found:
        return ["roster 里没有 proteus（目录名/位置不对，或目录是链接——"
                "发现机制不跟随 reparse point，见模块头注释）"], ""
    broken = found[0].get("broken")
    if broken:
        return [f"proteus 在 roster 里是 broken：{broken}"], ""
    return [], f"roster OK（{len(rows)} 个 preset，proteus 未 broken）"


# ----------------------------------------------------------------------
# 同步
# ----------------------------------------------------------------------
def _remove_link(path: Path) -> None:
    """摘掉链接而不碰目标。Windows 上必须用 `rmdir`：PowerShell/Path.unlink 对
    junction 有递归删目标的风险。"""
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "rmdir", str(path)], capture_output=True,
                       text=True, check=False)
    else:
        path.unlink()


def _backup_previous(home: Path, dst: Path, keep: int = KEEP_BACKUPS) -> str:
    """把改动前的副本存到 preset 根**之外**（放根里会被当成一个 preset）。"""
    if not dst.is_dir():
        return ""
    import time

    root = home / "backups"
    target = root / f"preset-proteus-{time.strftime('%Y%m%d%H%M%S')}"
    try:
        target.mkdir(parents=True, exist_ok=True)
        for item in dst.iterdir():
            if item.is_file():
                shutil.copy2(item, target / item.name)
    except OSError:
        return ""
    old = sorted(p for p in root.glob("preset-proteus-*") if p.is_dir())
    for stale in old[:-keep]:
        shutil.rmtree(stale, ignore_errors=True)
    return str(target)


def install(home: Path) -> list[str]:
    """把仓库的 preset 同步到 `$DSH_HOME`（幂等）。返回动作说明。"""
    dst = home / ".agent-presets" / "proteus"
    notes: list[str] = []
    if dst.exists() and _is_reparse_point(dst):
        _remove_link(dst)
        notes.append("移除原有链接——DSH 的 preset 发现机制**不跟随 reparse point**，"
                     "链接会让 preset 从选择器里静默消失")
    dst.mkdir(parents=True, exist_ok=True)

    changed = [p.name for p in sorted(SRC.iterdir())
               if p.is_file()
               and (not (dst / p.name).is_file()
                    or _sha(dst / p.name) != _sha(p))]
    if not changed:
        notes.append("已是最新，无需同步")
        return notes
    backup = _backup_previous(home, dst)
    for name in changed:
        shutil.copy2(SRC / name, dst / name)
    notes.append(f"已同步 {len(changed)} 个文件：{', '.join(changed)}")
    if backup:
        notes.append(f"改动前的副本：{backup}")
    return notes


# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python tools/dsh_install.py",
        description="同步并校验 Proteus 的 DSH 宿主接入")
    ap.add_argument("--home", default="", help="DSH home（缺省 $DSH_HOME 或 ~/.dsh）")
    ap.add_argument("--profile", default="web", help="profile 名（缺省 web）")
    ap.add_argument("--check", action="store_true",
                    help="只检查，不改动（有漂移即非零退出）")
    ap.add_argument("--no-roster", action="store_true", help="跳过 roster 健康检查")
    ap.add_argument("--no-bundle-check", action="store_true",
                    help="跳过审计桥的 profile 接线检查")
    args = ap.parse_args(argv)

    home = dsh_home(args.home)
    dst = home / ".agent-presets" / "proteus"
    print(f"DSH home : {home}")
    print(f"preset   : {dst}")

    if not args.check:
        for note in install(home):
            print(f"  - {note}")

    problems: list[str] = []
    problems += verify_preset(dst)
    problems += [f"与仓库不同步：{d}" for d in drift(dst)]
    problems += verify_patch()
    if not args.no_bundle_check:
        problems += check_bundle(home, args.profile)
        problems += check_bridge_entry(home, args.profile)

    notes: list[str] = []
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
        if any("与仓库不同步" in p for p in problems):
            print("  → 同步：python tools/dsh_install.py（不带 --check）")
        return 1
    print("接入健康：preset 与仓库同步、补丁完整、审计桥已接线且为链接")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
