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


def verify_gate_consistency(preset: Path | None = None,
                            patch: Path | None = None) -> list[str]:
    """内核的 ask 档被 `--authorize` 抬起时，宿主侧必须仍有一个"会问人"的档位。

    **为什么需要这条（R-13 收口）**：MCP 是**非交互**通道，内核的 `ask` 档没有
    可以被问的人——`Policy.check` 对 ask / dangerous 一律 `return False`
    （是**拒绝**，不是弹窗）。所以 preset 的 MCP 行必须在服务端启动时就
    `--authorize`，否则 sqlmap / nuclei / ffuf 这类工具全部不可用，模型只能转而
    用宿主 shell——正是 R-1 与 R-11 那个"为了能用而放弃保护"的恶性循环。

    代价是：DTO 会话里内核的 ask 档**不再是人的闸门**。于是"人"那道闸只剩 DSH 的
    `approval` 档位。本条把这件事变成**可机检的不变量**：

        抬起了内层 ask  ⇒  host 补丁里至少要有一个 `approval: ask` 的档位

    三档全 `never`（无人值守最宽姿态）会被直接报出来。
    """
    cfg = preset or (SRC / "agent.cordis.yml")
    patch_path = patch or PATCH
    if not cfg.is_file() or not patch_path.is_file():
        return []

    uses_authorize = False
    try:
        rows = _yaml_rows(cfg)
    except Exception:                             # noqa: BLE001 - 解析问题另有检查
        return []
    for row in rows:
        # 真实 preset 里 `args` 在行的 `config` 之下（不是行顶层）
        block = row.get("config")
        args = block.get("args") if isinstance(block, dict) else None
        if isinstance(args, str):
            args = [args]
        if isinstance(args, list) and "--authorize" in [str(a) for a in args]:
            uses_authorize = True
            break
    if not uses_authorize:
        return []

    if "approval: ask" not in patch_path.read_text(encoding="utf-8"):
        return ["preset 的 MCP 行抬起了内核 ask 档（--authorize），但 host 补丁里"
                "**没有任何 approval: ask 的档位**——DSH 会话将完全没有人工确认"
                "环节。要么给某个档位恢复 approval: ask，要么去掉 --authorize"
                "（代价见 docs/修复待办清单.md R-13）"]
    return []


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
# 运行态：进程是否加载了当前安装的模块
# ----------------------------------------------------------------------
DEFAULT_WEB_PORT = 4080


def _system_exe(name: str, subdir: str = "") -> str:
    """系统 exe 的绝对路径——**不依赖 PATH**。

    双击启动器时的环境可能是残缺的（实测：最小环境下 PATH 里既没有
    `powershell` 也没有 `node`），于是进程枚举"静默返回空"、旧实例不会被关掉，
    又要撞 EADDRINUSE。系统目录用 `%SystemRoot%` / `%ProgramFiles%` 拼，
    不写死本机路径（硬规则 7）。
    """
    found = shutil.which(name)
    if found:
        return found
    if os.name != "nt":
        return ""
    root = Path(os.environ.get("SystemRoot", "C:\\Windows"))
    candidates = [root / "System32" / f"{name}.exe"]
    if subdir:
        candidates.insert(0, root / "System32" / subdir / f"{name}.exe")
    if name == "node":
        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        candidates.append(Path(program_files) / "nodejs" / "node.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def _powershell() -> str:
    found = shutil.which("powershell")
    if found:
        return found
    if os.name != "nt":
        return ""
    exe = (Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
           / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    return str(exe) if exe.is_file() else ""


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """端口在听吗（纯 socket，不依赖任何外部命令）。"""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


def port_owner_pids(port: int) -> list[int]:
    """谁占着这个端口（解析 `netstat -ano`；同样不依赖 PATH）。"""
    netstat = _system_exe("netstat")
    if not netstat:
        return []
    try:
        proc = subprocess.run([netstat, "-ano"], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    pids: list[int] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or "LISTENING" not in line.upper():
            continue
        if not parts[1].endswith(f":{port}"):
            continue
        if parts[-1].isdigit():
            pids.append(int(parts[-1]))
    return sorted(set(pids))


def wait_port_free(port: int, timeout: float = 20.0) -> bool:
    """等端口真的释放（不等就会又撞 EADDRINUSE）。"""
    import time as _time

    deadline = _time.time() + timeout
    while _time.time() < deadline:
        if not port_in_use(port):
            return True
        _time.sleep(0.5)
    return not port_in_use(port)


def terminate_pids(pids: list[int]) -> list[str]:
    """按 pid 结束进程（Windows 用 `taskkill /T`，连子进程一起）。"""
    notes: list[str] = []
    for pid in pids:
        if os.name == "nt":
            subprocess.run([_system_exe("taskkill") or "taskkill",
                            "/PID", str(pid), "/T", "/F"],
                           capture_output=True, text=True, check=False)
        else:
            try:
                os.kill(int(pid), 15)
            except (OSError, ValueError):
                pass
        notes.append(f"已结束进程 pid={pid}")
    return notes


def _is_dsh_cmdline(cmd: str, profile: str) -> bool:
    """这条命令行是不是"这个 profile 的 DSH"。

    必须兼容两种启动姿势（2026-09-23 实测）：启动器的
    `apps/cli/lib/bin.js --profile web …` 与源码/开发模式的
    `apps/cli/src/bin.ts "web"`。只认前一种会让运行态检查**静默跳过**
    ——看起来"通过"，其实什么都没查（实测就是这么漏过去的）。
    """
    # 命令行里两种分隔符都会出现（Windows 实际是反斜杠：apps\cli\lib\bin.js），
    # 只匹配正斜杠会让运行态检查**静默跳过**——真实命令行实测就是这么漏的。
    text = cmd.replace("\\", "/")
    if "apps/cli/lib/bin.js" not in text and "apps/cli/src/bin.ts" not in text:
        return False
    if f"--profile {profile}" in text or f"--profile={profile}" in text:
        return True
    return f'"{profile}"' in text or f" {profile}" in text


def running_dsh(profile: str) -> list[dict]:
    """正在跑该 profile 的 DSH 进程（`pid` / `start` / `cmd`）。

    仅 Windows 尽力而为——拿不到就返回空表（调用方据此跳过，而不是报错）。
    """
    if os.name != "nt":
        return []
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | "
        "Where-Object { $_.CommandLine -like '*apps/cli/lib/bin.js*' "
        "-or $_.CommandLine -like '*apps/cli/src/bin.ts*' } | "
        "ForEach-Object { [pscustomobject]@{ pid = $_.ProcessId; "
        "start = $_.CreationDate.ToString('o'); cmd = $_.CommandLine } } | "
        "ConvertTo-Json -Compress"
    )
    shell = _powershell()
    if not shell:
        return []
    try:
        proc = subprocess.run([shell, "-NoProfile", "-Command", ps],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    return [r for r in rows
            if isinstance(r, dict) and _is_dsh_cmdline(r.get("cmd") or "", profile)]


def _parse_start(value: str) -> float:
    """把 `CreationDate.ToString('o')` 解析成时间戳；解析不了返回 0。

    退化路径：.NET 的 'o' 带 7 位小数，部分 Python 的 `fromisoformat` 不接受，
    截到秒即可——这里只用来比先后，不需要亚秒精度。
    """
    import datetime

    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text[:19]):
        try:
            return datetime.datetime.fromisoformat(candidate).timestamp()
        except ValueError:
            continue
    return 0.0


def live_check(profile: str, dst: Path) -> list[str]:
    """改了的模块，正在跑的进程里**是不是真的生效了**。

    这条补的是最后一个静默失效面：文件同步对了、`--check` 也过了，但 Node 的
    ESM 缓存**不重启不更新**（指南 §5.1 记过这个坑）——进程仍在跑旧模块，而
    从会话里完全看不出来。判据：进程启动时间 vs 安装文件的最新改动时间。
    """
    procs = running_dsh(profile)
    if not procs:
        return []
    newest = max((p.stat().st_mtime for p in dst.iterdir() if p.is_file()),
                 default=0.0)
    if newest == 0.0:
        return []
    import time as _time

    stamp = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(newest))
    problems = []
    for proc in procs:
        started = _parse_start(proc.get("start", ""))
        if started and started < newest:
            problems.append(
                f"DSH 进程 pid={proc.get('pid')} 启动于 "
                f"{str(proc.get('start'))[:19]}，早于安装文件的最新改动（{stamp}）"
                f"——Node 的 ESM 缓存不重启不更新，该进程加载的仍是旧模块。"
                f"重启 DSH 后本项即消失")
    return problems


def _confirm() -> bool:
    """交互确认；stdin 不是终端、读不到、被打断——一律当"否"（安全默认）。

    **不要依赖它**：实测在重定向/异常 stdin 下 `input()` 会抛 `EOFError` 把整个
    启动流程崩掉（双击启动器那次就是这么失败的）。所以它只在 `--ask` 下用，
    默认路径根本不问。
    """
    if not sys.stdin.isatty():
        return False
    try:
        return input("  关闭它并继续启动？[y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def terminate_dsh(procs: list[dict]) -> list[str]:
    """结束这些 DSH 进程（Windows 用 `taskkill /T`，连子进程一起）。"""
    notes: list[str] = []
    for proc in procs:
        pid = proc.get("pid")
        if not pid:
            continue
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, text=True, check=False)
        else:
            try:
                os.kill(int(pid), 15)
            except (OSError, ValueError):
                pass
        notes.append(f"已结束 DSH 进程 pid={pid}")
    return notes


def wait_gone(procs: list[dict], profile: str = "web",
              timeout: float = 15.0) -> bool:
    """等这些进程真的退出（端口释放需要一点时间，不等就会又撞 EADDRINUSE）。"""
    import time as _time

    pids = {str(p.get("pid")) for p in procs if p.get("pid")}
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        alive = {str(p.get("pid")) for p in running_dsh(profile)}
        if not (pids & alive):
            return True
        _time.sleep(0.5)
    return False


def _env_file_value(key: str) -> str:
    """从不入库的 `.env` 里取一个键（与 penagent/envcfg.py 同一约定）。

    启动器不能再强依赖 `PENTEST_WS`：双击场景下环境变量可能没继承到
    （setx 之后没重启 Explorer 就是这种），而 `.env` 就在仓库里、一定能读到。
    """
    env_file = REPO / ".env"
    if not env_file.is_file():
        return ""
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return ""


def workspace_root() -> Path:
    """工作区根：环境变量 → `.env` → 仓库的上一级（相邻布局）。"""
    for candidate in (os.environ.get("PENTEST_WS", "").strip(),
                      _env_file_value("PENTEST_WS")):
        if candidate:
            return Path(candidate)
    return REPO.parent


def verify_launcher(path: Path | None = None) -> list[str]:
    """`start-proteus.cmd` 必须是 CRLF 行尾。

    这条不是洁癖：**LF-only 的 .cmd 会被 cmd.exe 错误分行**——`rem` 后面的
    中文与下一行被拼成一条命令去执行，窗口一闪就退，用户看到的就是"点了没反应"
    （2026-09-23 实测：同一内容 LF 下 11 行乱码报错，CRLF 下正常）。
    """
    cmd = path or REPO / "dsh" / "start-proteus.cmd"
    if not cmd.is_file():
        return [f"启动器不存在：{cmd}"]
    # **必须按字节读**：Path.read_text() 默认做通用换行转换（CRLF → LF），
    # 那样永远看不到 CRLF，正确的文件也会被判成 LF-only（第一版就是这么错的）。
    data = cmd.read_bytes()
    bare_lf = data.count(b"\n") - data.count(b"\r\n")
    if bare_lf > 0:
        return [f"{cmd.name} 有 {bare_lf} 行是 LF 行尾（必须是 CRLF）——"
                f"cmd.exe 会把这些行拼错，表现为双击后窗口一闪、什么都没发生"]
    return []


def launch(profile: str, dst: Path, port: int = DEFAULT_WEB_PORT) -> int:
    """同步 + 关旧实例 + 启动 DSH（启动器调用的入口）。

    逻辑放这里而不是 `.cmd` 里：cmd 的解析与引号是另一套语言，踩过一次就够
    （LF 行尾）；Python 这边可单测、能给清楚的错误、还能回落到 `.env`。
    """
    for note in install(dst.parent.parent):
        print(f"  - {note}")

    # 旧实例按**端口**关，不按进程枚举：双击场景下 PATH 可能残缺，枚举会静默返回
    # 空——那正是"新实例又撞 EADDRINUSE"的成因。端口判据不依赖任何外部命令。
    if port_in_use(port):
        pids = port_owner_pids(port)
        print(f"检测到 {port} 端口被占用（pid={pids or '未知'}）——先关掉它再启动"
              f"（否则新实例会以 EADDRINUSE 127.0.0.1:{port} 失败退出）。")
        print("  注意：关掉它 = 当前 GUI 会话结束（对话本身是持久化的）。")
        if pids:
            for note in terminate_pids(pids):
                print(f"  - {note}")
        else:
            print("  ! 查不到占用者 pid（netstat 不可用）——请手动结束它。")
            return 1
        if not wait_port_free(port):
            print(f"  ! {port} 端口未在 20 秒内释放——请手动结束它再启动。")
            return 1
        print(f"  - {port} 端口已释放")

    dsh_dir = workspace_root() / "deepseek-harness"
    bin_js = dsh_dir / "apps" / "cli" / "lib" / "bin.js"
    if not bin_js.is_file():
        print(f"  ! 找不到 DSH 入口：{bin_js}")
        print(f"    工作区根解析为 {workspace_root()}（可用 PENTEST_WS 或 .env 覆盖）")
        return 1
    node = _system_exe("node")
    if not node:
        print("  ! 找不到 node.exe（PATH 与 %ProgramFiles%\\nodejs 都没有）")
        return 1
    # 参数逐个内联成字面量列表、不经 shell（shell=False 是默认）：三个元素都来自
    # 「已校验存在的绝对路径」或命令行选项，没有拼接进字符串再解释的环节。
    print(f"  - 启动：{node} {bin_js} --profile {profile} --patch {PATCH}")
    try:
        return subprocess.run([node, str(bin_js), "--profile", profile,
                               "--patch", str(PATCH)],
                              cwd=dsh_dir, check=False).returncode
    except OSError as exc:
        print(f"  ! 启动失败：{exc}")
        return 1


def bridge_live_check(spool: Path) -> tuple[list[str], str]:
    """审计桥是不是在跑**当前**代码——判据：spool 最新记录有没有 `preset` 字段。

    这条**不依赖"怎么启动的"**：老代码从不写 `preset`，新代码必写。进程检查
    （`live_check`）是辅助——它在识别不出进程时会跳过，而这条不会。
    """
    if not spool.is_file():
        return [], f"暂无 spool（{spool}）：还没有会话产生过工具调用"
    recent: list[dict] = []
    for line in reversed(spool.read_text(encoding="utf-8",
                                         errors="replace").splitlines()):
        if not line.strip():
            continue
        try:
            recent.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(recent) >= 5:
            break
    if not recent:
        return [], "spool 里没有可解析记录，跳过审计桥活体检查"
    if any("preset" in rec for rec in recent):
        return [], "审计桥已在跑当前代码（最新记录带 preset 归属）"
    return ["审计桥仍在跑旧代码：spool 最新记录没有 preset 字段"
            "（老代码从不写它）——重启 DSH 才会加载新模块"], ""


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
    ap.add_argument("--spool", default="",
                    help="宿主桥 spool 路径（缺省 <仓库>/data/dsh-events.jsonl）")
    ap.add_argument("--no-live", action="store_true",
                    help="跳过运行态检查（进程模块 / 审计桥代码是否为当前版本）")
    ap.add_argument("--port", type=int, default=DEFAULT_WEB_PORT,
                    help=f"web profile 的监听端口（缺省 {DEFAULT_WEB_PORT}）")
    ap.add_argument("--launch", action="store_true",
                    help="启动器用：同步 + 关旧实例 + 启动 DSH（逻辑在 Python 里，"
                         "不依赖 cmd 解析与环境变量）")
    ap.add_argument("--restart", action="store_true",
                    help="启动器用：若已有实例在跑，先关掉它再继续"
                         "（否则新实例会以 EADDRINUSE 127.0.0.1:4080 失败退出）")
    ap.add_argument("--ask", action="store_true",
                    help="配合 --restart：关之前问一句（默认不问——双击启动器"
                         "已经是明确的启动意图，而问一句会多一个失败点）")
    ap.add_argument("--no-bundle-check", action="store_true",
                    help="跳过审计桥的 profile 接线检查")
    args = ap.parse_args(argv)

    # 控制台可能是 GBK（双击/普通 cmd），而输出里有中文与 · ✗ 这类字符——
    # 不兜住就是 UnicodeEncodeError 崩栈，用户看到 traceback 而不是问题清单。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    home = dsh_home(args.home)
    dst = home / ".agent-presets" / "proteus"
    print(f"DSH home : {home}")
    print(f"preset   : {dst}")

    if args.launch:
        return launch(args.profile, dst, port=args.port)

    if not args.check:
        for note in install(home):
            print(f"  - {note}")

    if args.restart:
        procs = running_dsh(args.profile)
        if procs:
            pids = ", ".join(str(p.get("pid")) for p in procs)
            print(f"检测到已有 DSH 实例在跑（pid={pids}）。不先关掉它，新实例会以"
                  f"\n  EADDRINUSE: address already in use 127.0.0.1:4080 失败退出"
                  f"\n  ——而双击启动器的人只会看到窗口一闪。")
            print("  注意：关掉它 = 当前 GUI 会话结束（对话本身是持久化的）。")
            agreed = True if not args.ask else _confirm()
            if not agreed:
                print("已取消：既没有关闭正在跑的实例，也没有启动新实例。")
                return 1
            for note in terminate_dsh(procs):
                print(f"  - {note}")
            if not wait_gone(procs, args.profile):
                print("  ! 进程未在 15 秒内退出——请手动结束它再启动。")
                return 1
            print("  - 端口已释放，可以启动新实例")

    problems: list[str] = []
    problems += verify_preset(dst)
    problems += [f"与仓库不同步：{d}" for d in drift(dst)]
    problems += verify_patch()
    problems += verify_gate_consistency()
    problems += verify_launcher()
    if not args.no_bundle_check:
        problems += check_bundle(home, args.profile)
        problems += check_bridge_entry(home, args.profile)
    notes: list[str] = []
    if not args.no_live:
        problems += live_check(args.profile, dst)
        bridge_problems, bridge_live_note = bridge_live_check(
            Path(args.spool) if args.spool else REPO / "data" / "dsh-events.jsonl")
        problems += bridge_problems
        if bridge_live_note:
            notes.append(bridge_live_note)

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
