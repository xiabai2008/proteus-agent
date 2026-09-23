"""DSH 兼容性自检：上游（deepseek-harness）更新后，Proteus 集成点还成不成立。

与 tools/dsh_install.py --check 的分工：
  - dsh_install --check   = 本侧一致性（我们装到 ~/.dsh 的副本 vs 仓库、roster、运行态）
  - dsh_compat_check      = 对侧兼容性（已装 harness 里，我们依赖的接口/包/行还在不在）

检查面（每一项都对应 dsh/ 下代码的真实调用点，来源见各项注释）：
  C1  引用的 @deepseek-ai 包都存在（preset 组合 + bridge 包）
  C2  persona 插件 API（systemPrompt.section / getSectionOrder / 分区名 / order 校验）
  C3  tools-policy 插件 API（session/event、agentPreset、tools/pre-execute 派发）
  C4  mcp-client 配置 schema（transport/serverName/command/cwd/env/超时/启动失败语义）
  C5  host 补丁目标行（dsh-base 组合里的 approval / permission 两行及其档位键）
  C6  CLI 入口（apps/cli/lib/bin.js + --profile/--patch 参数）
  C7  版本锁漂移（dsh/DSH_VERSION.lock vs harness 当前 HEAD）

上游漂移时的处置：跑本检查 → 按 FAIL 项定位断点 → 修复集成（preset/插件/补丁）→
真机冒烟（指南第五节）→ 更新 DSH_VERSION.lock。**升级 DSH 前先跑一次本检查做基线。**
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRESET_DIR = ROOT / "dsh" / ".agent-presets" / "proteus"
BRIDGE_PKG = ROOT / "dsh" / "proteus-bridge" / "package.json"
LOCK = ROOT / "dsh" / "DSH_VERSION.lock"


def profiles_nm() -> Path:
    override = os.environ.get("DSH_PROFILES_NM", "")
    base = Path(override) if override else Path.home() / ".dsh" / "profiles"
    return base / "node_modules" / "@deepseek-ai"


def harness_repo() -> Path | None:
    env = os.environ.get("PENTEST_DSH_REPO", "")
    if env:
        p = Path(env)
        return p if p.exists() else None
    ws = os.environ.get("PENTEST_WS", "")
    candidates = ([Path(ws) / "deepseek-harness"] if ws else []) + [
        ROOT.parent / "deepseek-harness"]
    for c in candidates:
        if (c / "apps" / "cli" / "lib" / "bin.js").exists():
            return c
    return None


def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def grep(pkg: str, needle: str, *, sub: str = "lib") -> bool:
    """在指定包的 lib 树（.js/.d.ts，跳过 .map）里找字符串。"""
    root = profiles_nm() / pkg / sub
    if not root.exists():
        root = profiles_nm() / pkg
    if not root.exists():
        return False
    for f in root.rglob("*"):
        if f.suffix not in (".js", ".ts") or f.suffix == ".map":
            continue
        if needle in read_text(f):
            return True
    return False


RESULTS: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    RESULTS.append((status, name, detail))


def parse_rows(yml: str) -> list[dict]:
    """轻量行解析：任意缩进的 `- id: X` 独立成块（含组内子行），
    后续行（name/disabled）归属最近的块。

    要点：不能只认顶层行——组（planning/compaction/delegation）的子行
    各自有 disabled 标记，若按顶层块聚合会把子行的 disabled 传染给整组，
    把"启用但缺包"误判成"占位容忍"（实测踩过）。
    不用 YAML 库：组合里的 !!js 标签 PyYAML 不认；我们只需要块级事实。
    """
    rows: list[dict] = []
    cur: dict | None = None
    for line in yml.splitlines():
        m = re.match(r"^\s*- id: (\S+)", line)
        if m:
            cur = {"id": m.group(1), "names": [], "disabled": False}
            rows.append(cur)
            continue
        if cur is None:
            continue
        if re.match(r"^\s*disabled: true\b", line):
            cur["disabled"] = True
        cur["names"] += re.findall(r"@deepseek-ai/([a-z0-9-]+)", line)
    return rows


def check_pkgs() -> None:
    yml = read_text(PRESET_DIR / "agent.cordis.yml")
    if not yml:
        record("FAIL", "C1 包存在性", f"preset 组合文件缺失：{PRESET_DIR / 'agent.cordis.yml'}")
        return
    nm = profiles_nm()
    enabled, disabled, missing = set(), set(), set()
    for row in parse_rows(yml):
        for pkg in row["names"]:
            if row["disabled"]:
                disabled.add(pkg)
            else:
                (enabled if (nm / pkg).is_dir() else missing).add(pkg)
    bridge = json.loads(read_text(BRIDGE_PKG) or "{}")
    for pkg in re.findall(r"@deepseek-ai/([a-z0-9-]+)",
                          json.dumps(bridge.get("dependencies", {}))):
        (enabled if (nm / pkg).is_dir() else missing).add(pkg)
    if missing:
        record("FAIL", "C1 包存在性",
               f"启用行缺失 {len(missing)} 个：{sorted(missing)}（上游改名/合并？）")
        return
    disabled_absent = sorted(p for p in disabled - enabled
                             if not (nm / p).is_dir())
    note = f"{len(enabled)} 个启用引用全部存在"
    if disabled_absent:
        note += f"；disabled 占位且本机无包（容忍）：{disabled_absent}"
    record("OK", "C1 包存在性", note)


def check_persona_api() -> None:
    need = {
        "getSectionOrder": "systemPrompt 的顺序查询 API",
        "deployment:persona-prefix": "前缀分区名",
        "deployment:persona-suffix": "后缀分区名",
        "order must be a finite number": "section() 的 order 校验语义",
    }
    missing = [k for k in need if not grep("dsh-system-prompt", k)]
    if missing:
        record("FAIL", "C2 persona 插件 API",
               f"缺失：{ {k: need[k] for k in missing} }")
    else:
        record("OK", "C2 persona 插件 API", "4 项接口全部健在")


def check_policy_api() -> None:
    checks = {
        ("dsh-session", "session/event"): "审计事件名（tools-policy 订阅）",
        ("dsh-session", "agentPreset"): "会话归属字段（SessionHeader）",
        ("dsh-tool-cordis", "tools/pre-execute"): "裁决钩子派发点",
    }
    missing = [f"{pkg}:{s}" for (pkg, s) in checks if not grep(pkg, s)]
    if missing:
        record("FAIL", "C3 tools-policy 插件 API", f"缺失：{missing}")
    else:
        record("OK", "C3 tools-policy 插件 API", "事件名/归属字段/裁决钩子全部健在")


def check_mcp_client_schema() -> None:
    need = ["serverName", "toolCallTimeoutMs", "failOnStartupError",
            "streamable-http", "transport"]
    missing = [k for k in need if not grep("dsh-mcp-client", k)]
    if missing:
        record("FAIL", "C4 mcp-client schema", f"缺失字段：{missing}")
    else:
        record("OK", "C4 mcp-client schema", "5 项字段全部健在")


def check_host_rows() -> None:
    host = profiles_nm() / "dsh-base" / "cordis.patch.yml"
    text = read_text(host)
    if not text:
        record("FAIL", "C5 host 补丁目标", f"dsh-base 组合文件缺失：{host}")
        return
    need = ["id: approval", "id: permission", "danger-full-access",
            "workspace-write", "read-only"]
    missing = [k for k in need if k not in text]
    if missing:
        record("FAIL", "C5 host 补丁目标", f"host 组合缺失：{missing}")
        return
    # 我们补丁里的每个行 id，host 里必须仍存在（整行替换语义的前提）
    ours = read_text(ROOT / "dsh" / "proteus.cordis.patch.yml")
    row_ids = re.findall(r"^- id: (\S+)", ours, re.M)
    orphan = [r for r in row_ids if f"id: {r}" not in text]
    if orphan:
        record("FAIL", "C5 host 补丁目标", f"补丁引用了 host 已不存在的行：{orphan}")
    else:
        record("OK", "C5 host 补丁目标", f"2 行 + 档位键齐；补丁行 {row_ids} 仍全部有效")


def check_cli_entry() -> None:
    repo = harness_repo()
    if repo is None:
        record("WARN", "C6 CLI 入口", "未定位到 harness 仓库（设 PENTEST_DSH_REPO 可显式指定）")
        return
    bin_js = repo / "apps" / "cli" / "lib" / "bin.js"
    src = bin_js.read_text(encoding="utf-8", errors="replace") \
        if bin_js.exists() else ""
    if not src:
        record("FAIL", "C6 CLI 入口", f"bin.js 缺失：{bin_js}")
        return
    missing = [f for f in ("--patch", "profile") if f not in src]
    if missing:
        record("FAIL", "C6 CLI 入口", f"bin.js 缺少参数：{missing}")
    else:
        record("OK", "C6 CLI 入口", "bin.js 存在且含 --patch/profile")


def check_version_lock() -> None:
    data = json.loads(read_text(LOCK) or "{}")
    locked = data.get("harness_commit", "")
    repo = harness_repo()
    if not locked:
        record("WARN", "C7 版本锁", "DSH_VERSION.lock 不存在或未记录 commit")
        return
    if repo is None:
        record("WARN", "C7 版本锁", f"锁={locked[:12]}…（harness 仓库未定位，跳过比对）")
        return
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo,
                              capture_output=True, text=True, timeout=15
                              ).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        record("WARN", "C7 版本锁", f"git 调用失败：{exc}")
        return
    if head and head != locked:
        record("WARN", "C7 版本锁",
               f"**上游已漂移**：锁定 {locked[:12]}… → 当前 {head[:12]}…；"
               "按上表修断点 → 冒烟 → 更新锁")
    else:
        record("OK", "C7 版本锁", f"harness 未漂移（{locked[:12]}…）")


CHECKS = [
    ("C1", check_pkgs),
    ("C2", check_persona_api),
    ("C3", check_policy_api),
    ("C4", check_mcp_client_schema),
    ("C5", check_host_rows),
    ("C6", check_cli_entry),
    ("C7", check_version_lock),
]


def main() -> int:
    quiet = "--quiet" in sys.argv
    for _, fn in CHECKS:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            record("FAIL", fn.__name__, f"检查自身异常：{exc}")
    fails = warns = 0
    for status, name, detail in RESULTS:
        if status == "OK" and quiet:
            continue
        print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
        fails += status == "FAIL"
        warns += status == "WARN"
    if not quiet:
        print(f"\n合计：{len(RESULTS)} 项，FAIL={fails}，WARN={warns}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
