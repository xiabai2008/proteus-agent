"""把 Proteus 的 agent preset 渲染成 bundle，并按**消费方视角**校验接入。

**2026-09-26 载体迁移（本文件第二版）**：安装版 DSH 0.1.7-rc.2 起，
`$DSH_HOME/.agent-presets/<id>/` 目录发现机制已被移除——安装版随附文档原文：
*"Before declaration rows, a user preset was a directory … Nothing reads that
directory any more."* preset 改为 `@deepseek-ai/dsh-agent-preset` 声明行，
由 **bundle 补丁**承载，用 `plugin_manager` `install_bundle` 装进 profile。

三条**真机实测**出来的解析规则（探针对照，2026-09-26；详见
docs/DSH主体化交付说明.md「桌面端 preset 载体」一节）：

1. bundle 补丁里插入声明行 → 生效；裸包名（`@deepseek-ai/dsh-*`）可解析；
2. `./x.mjs` 相对行的解析基准是 **profile 目录**，不是 bundle 目录
   （文件只在 bundle 里 → `broken: "never started"`；只在 profile 里 → 正常）；
3. **包自引用子路径**（`<包名>/<exports 子路径>`）可解析 —— 本仓库采用这条，
   四个共享插件因此留在 bundle 内，profile 目录不再需要副本。

据此，本工具的职责收敛为两件事：

* **渲染**：`tools/render_preset_bundle.py` 从 `dsh/.agent-presets/_shared/` 生成
  `dsh/proteus-presets/`（三个声明 + 一条 host 平面审计行）；
* **校验**：不再查"安装副本 vs 仓库"，而是查**消费方真会读到什么**——
  bundle 与来源一致、声明行齐全且不含必然 broken 的写法、profile 清单已登记该
  bundle、以及**运行中 DSH 的 roster** 里三个 preset 都在且没有 broken。

安装本身由 DSH 自己完成（官方文档明确要求不要用 shell 复现那一步）：

    plugin_manager → action: install_bundle → target: <仓库>/dsh/proteus-presets

用法（仓库根执行）：

    python tools/dsh_install.py             # 渲染 bundle + 校验（幂等）
    python tools/dsh_install.py --check     # 只检查，不改动；有问题即非零退出
    python tools/dsh_install.py --profile desktop --roster-port 19387

退出码：0 = 健康；1 = 有未决问题。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
BUNDLE_DIR = REPO / "dsh" / "proteus-presets"
PATCH = REPO / "dsh" / "proteus.cordis.patch.yml"
BRIDGE_NAME = "dsh-proteus-bridge"
BRIDGE_SRC = REPO / "dsh" / "proteus-bridge"
PROTECTED_TIERS = ("proteus-safe", "proteus-standard", "proteus-ctf")
PRESET_IDS = ("proteus-pentest", "proteus-ctf-web", "proteus-ctf-crypto")


def _load_renderer():
    """按路径加载渲染器（同目录的兄弟模块，不依赖 sys.path 上有 tools/）。"""
    import importlib.util

    path = Path(__file__).resolve().parent / "render_preset_bundle.py"
    spec = importlib.util.spec_from_file_location("render_preset_bundle", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)                 # type: ignore[union-attr]
    return mod


bundle = _load_renderer()
# 模式取值以渲染器为唯一来源（此处只是别名——不再自己维护第二份 PRESETS）。
# 键名保持 dict 形态：调用方按 `cfg["mode"]` 等取值。
PRESETS: dict[str, dict[str, str]] = {cfg["id"]: cfg for cfg in bundle.PRESETS}
SHARED_FILES: tuple[str, ...] = tuple(bundle.SHARED_FILES)

# 三个 preset（P0-6，2026-09-24 拍板 D1/D2）：同一份模板 + 同一份共享实现，
# 差异只有"默认模式 / 人格文件 / 会话状态键 / 显示名与排序"。
PRESETS: dict[str, dict[str, str]] = {
    "proteus-pentest": {
        "label": "渗透场景",
        "mode": "pentest-standard",
        "persona": "dsh-persona.md",
        "session_key": "pentest",
    },
    "proteus-ctf-web": {
        "label": "CTF Web 场景",
        "mode": "ctf-web",
        "persona": "dsh-persona-ctf.md",
        "session_key": "ctf-web",
    },
    "proteus-ctf-crypto": {
        "label": "CTF Crypto 场景",
        "mode": "ctf-crypto",
        "persona": "dsh-persona-ctf.md",
        "session_key": "ctf-crypto",
    },
}


def bundle_problems(bundle_dir: Path = BUNDLE_DIR) -> list[str]:
    """bundle 产物 vs `_shared/` 来源——判据同渲染器 `--check`（跑旧代码的防线）。

    渲染器是唯一来源：模板改了、插件改了而 bundle 没重渲染，这里就报出来。
    四个共享插件按**字节**比对（它们是副本，编解码会改行尾）。
    """
    problems: list[str] = []
    if not bundle_dir.is_dir():
        return [f"bundle 目录不存在：{bundle_dir}（跑：python tools/render_preset_bundle.py）"]
    for name, want in bundle.expected_files().items():
        target = bundle_dir / name
        if not target.is_file():
            problems.append(f"缺少 {name}（仓库里有）")
        elif target.read_text(encoding="utf-8") != want:
            problems.append(f"{name} 已过期（来源改了但没重渲染）")
    for name in bundle.copy_files():
        target = bundle_dir / name
        if not target.is_file():
            problems.append(f"缺少 {name}（仓库里有）")
        elif target.read_bytes() != (Path(bundle.SHARED) / name).read_bytes():
            problems.append(f"{name} 与 _shared/ 实现漂移")
    return problems


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


def _walk_dicts(node):
    """递归遍历 YAML 结构里的所有 dict。

    bundle 补丁把声明行嵌在 `insert` 之下、子插件又嵌在 `config.plugins` 之下，
    所以逐层看顶层行是不够的（旧的 preset 组合文件才是平铺的）。
    """
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)


def _yaml_rows(path: Path) -> list[dict]:
    """读 composition 的插件行，**容忍未知 tag**（`!!js` 是自定义 tag）。"""
    return _yaml_rows_text(path.read_text(encoding="utf-8"))


def _yaml_rows_text(text: str) -> list[dict]:
    """从文本解析插件行（与 `_yaml_rows` 同一实现，供渲染后的文本直接用）。"""
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
    data = yaml.load(text, Loader=_Tolerant)
    return [row for row in (data or []) if isinstance(row, dict)]


def verify_bundle(bundle_dir: Path = BUNDLE_DIR) -> list[str]:
    """bundle 自身的可机检不变量（每条都对应一种"静默失效"）。

    为什么判据落在这份文件上：`install_bundle` 装进去的就是它——声明行的写法
    决定 preset 能不能进选择器，而**失败的 preset 只是不进列表、界面零提示**。
    """
    problems = bundle_problems(bundle_dir)
    patch = bundle_dir / "cordis.patch.yml"
    if not patch.is_file():
        return problems
    text = patch.read_text(encoding="utf-8")

    # 1) 三个声明行齐全（少一个 = 选择器里少一个入口，且没有任何提示）
    for preset_id in PRESET_IDS:
        if f"    - id: preset-{preset_id}\n" not in text:
            problems.append(f"bundle 里缺声明行 preset-{preset_id}"
                            f"（该场景不会出现在选择器里）")

    # 2) 渲染漏占位符 = 行 config 变字面量
    for token in ("{{PRESET_ID}}", "{{PRESET_LABEL}}", "{{DEFAULT_MODE}}",
                  "{{PERSONA_PROMPT}}", "{{SESSION_KEY}}"):
        if token in text:
            problems.append(f"bundle 补丁里还有未替换的占位符 {token}")

    # 3) `!!js` 尾部出现 ": " 会被 YAML 拆成映射键（求值得到 [object Object]）。
    #    先扫原始行：YAML 自己解析失败时报的是泛泛的
    #    "mapping values are not allowed here"，真正的原因会被盖掉。
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#") or "!!js" not in line:
            continue
        if ": " in line.split("!!js", 1)[1]:
            problems.append(
                f"bundle 第 {lineno} 行的 !!js 表达式含 ': '（YAML 会拆成映射键，"
                f"求值得到 [object Object]）：{line.strip()[:70]}")

    try:
        rows = _yaml_rows(patch)
    except Exception as exc:                      # noqa: BLE001 - 解析失败本身要报
        problems.append(f"bundle 补丁解析失败：{exc}")
        return problems

    # 4) 绝不允许 './x.mjs' 相对行：实测解析基准是 **profile 目录**，bundle 内的
    #    相对行必然 broken（"never started"），且 broken 的 preset 不进选择器。
    for row in _walk_dicts(rows):
        spec = row.get("name")
        if not isinstance(spec, str) or not spec.startswith(("./", "../")):
            continue
        problems.append(
            f"bundle 插件行 {row.get('id')!r} 用了相对 specifier {spec}"
            f"——新机制下按 profile 目录解析，必然 broken；"
            f"应改为包自引用子路径（{bundle.BUNDLE_NAME}/<key>）")

    # 5) exports 必须覆盖四个插件（包自引用能解析的前提）
    pkg = bundle_dir / "package.json"
    if pkg.is_file():
        try:
            exports = json.loads(pkg.read_text(encoding="utf-8"))["exports"]
        except Exception as exc:                  # noqa: BLE001
            problems.append(f"package.json 读不出 exports：{exc}")
        else:
            for key in bundle.SHARED_FILES.values():
                if f"./{key}" not in exports:
                    problems.append(f"package.json 的 exports 缺 ./{key}"
                                    f"（对应插件行解析不到，preset 会 broken）")
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
    if preset is None:
        # 三个声明都在同一份 bundle 补丁里，读它即可（旧版是渲染后的组合文件）
        preset = BUNDLE_DIR / "cordis.patch.yml"
    if not preset.is_file():
        return []
    return verify_gate_consistency_text(preset.read_text(encoding="utf-8"), patch)


def verify_gate_consistency_text(text: str,
                                 patch: Path | None = None) -> list[str]:
    patch_path = patch or PATCH
    if not text or not patch_path.is_file():
        return []

    uses_authorize = False
    try:
        rows = _yaml_rows_text(text)
    except Exception:                             # noqa: BLE001 - 解析问题另有检查
        return []
    for row in _walk_dicts(rows):
        # `args` 在行的 `config` 之下（bundle 里还要再深两层：insert/config.plugins）
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


def _rpc_cookie(home: Path, origin: str) -> str | None:
    """铸一个 DSH web 会话 cookie（与 `tools/dsh_desktop_rpc.mjs` 同一套做法）。

    为什么要走到这一步：preset 是否真的进了选择器，只有**运行中的 DSH**知道。
    凭据取自 `$DSH_HOME/.credentials.yaml`，请求只发 127.0.0.1，不引入新依赖。
    """
    creds = home / ".credentials.yaml"
    try:
        text = creds.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(
        r"client-connection/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)",
        text)
    if match is None:
        return None

    def _b64url(raw: bytes) -> str:
        return (base64.b64encode(raw).decode()
                .replace("+", "-").replace("/", "_").rstrip("="))

    encoded = match.group(1)
    pad = "=" * ((4 - len(encoded) % 4) % 4)
    secret = base64.b64decode(encoded.replace("-", "+").replace("_", "/") + pad)
    authority = urlparse(origin).netloc
    name = "dsh-auth-" + _b64url(hashlib.sha256(authority.encode()).digest())
    issued = int(time.time() * 1000)
    payload = json.dumps({"version": 1, "authority": authority, "issuedAt": issued,
                          "expiresAt": issued + 86_400_000}, separators=(",", ":"))
    body = _b64url(payload.encode())
    sig = _b64url(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{name}=v1.{body}.{sig}"


def rpc_call(home: Path, port: int, method: str,
             args: dict | None = None) -> tuple[dict | None, str]:
    """对运行中的 DSH 发一次只读 RPC；返回 (结果, 说明)。失败不抛。"""
    origin = f"http://127.0.0.1:{port}"
    cookie = _rpc_cookie(home, origin)
    if cookie is None:
        return None, f"跳过（{home / '.credentials.yaml'} 里没有 browser-session 凭据）"
    body = json.dumps({"type": "client-request", "rpcId": "dsh-install-check",
                       "method": method,
                       "payload": {"args": args or {}}}).encode("utf-8")
    req = urllib.request.Request(
        f"{origin}/api/{method}", data=body,
        headers={"content-type": "application/json", "cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode("utf-8")), ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"跳过（{origin} 不可达：{exc}）"


def roster_live(home: Path, ports: tuple[int, ...] = (),
                preset_ids: tuple[str, ...] | None = None
                ) -> tuple[list[str], str]:
    """读**运行中 DSH** 的 roster；返回 (问题, 说明)。

    为什么不再用 `discoverPresets`：那个 API 只存在于 0.1.6 时代的
    `dsh-agent-presets` 包里，安装版 0.1.7-rc.2 的 app.asar 里**一次都不出现**
    （字节级扫描 0 命中）。判据继续挂在它身上，就会在"桌面端一个 Proteus preset
    都读不到"时报"接入健康"——2026-09-26 实测正是这么被骗过去的。
    """
    want = preset_ids or PRESET_IDS
    tried: list[int] = []
    for port in (ports or (19387, 4080)):
        tried.append(port)
        data, note = rpc_call(home, port, "agentPresets/list")
        if data is None:
            continue
        presets = (((data.get("result") or {}).get("value") or {})
                   .get("presets") or [])
        if not presets:
            return ["运行中的 DSH 返回了空 roster——RPC 形状变了？"], ""
        problems: list[str] = []
        have = {p.get("id") for p in presets if isinstance(p, dict)}
        for preset_id in want:
            if preset_id not in have:
                problems.append(
                    f"运行中的 DSH roster 里没有 {preset_id}"
                    f"（bundle 没装上 / 声明行写错 / 激活失败——"
                    f"三种都在界面上零提示）")
                continue
            broken = next((p.get("broken") for p in presets
                           if isinstance(p, dict) and p.get("id") == preset_id), None)
            if broken:
                problems.append(f"{preset_id} 在 roster 里是 broken：{broken}"
                                f"（该 preset 无法组成会话，且不进选择器）")
        if problems:
            return problems, ""
        return [], (f"roster OK（{len(presets)} 个 preset，"
                    f"{'/'.join(want)} 均在且未 broken；端口 {port}）")
    return [], f"跳过 roster 检查（端口 {tried or [19387, 4080]} 均不可达）"


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


def live_check(profile: str, dirs: list[Path]) -> list[str]:
    """改了的模块，正在跑的进程里**是不是真的生效了**。

    这条补的是最后一个静默失效面：文件同步对了、`--check` 也过了，但 Node 的
    ESM 缓存**不重启不更新**（指南 §5.1 记过这个坑）——进程仍在跑旧模块，而
    从会话里完全看不出来。判据：进程启动时间 vs 安装文件的最新改动时间
    （三个 preset 取最大）。
    """
    procs = running_dsh(profile)
    if not procs:
        return []
    newest = max((p.stat().st_mtime
                  for dst in dirs if dst.is_dir()
                  for p in dst.iterdir() if p.is_file()),
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
    """启动 `.cmd` 必须是 CRLF 行尾。

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


def verify_launchers() -> list[str]:
    """仓库里**所有** `.cmd` 启动器都要过 CRLF 检查。

    单独一个 `verify_launcher` 只管一个文件，新加启动器很容易漏——桌面端启动器
    就是这么漏进仓库的（2026-09-26 由路径卫生用例顺带发现它还是 LF）。
    """
    problems: list[str] = []
    for cmd in (REPO / "dsh" / "start-proteus.cmd",
                REPO / "tools" / "launch_dsh_desktop.cmd"):
        problems += verify_launcher(cmd)
    return problems


def launch(profile: str, home: Path, port: int = DEFAULT_WEB_PORT) -> int:
    """渲染 bundle + 关旧实例 + 启动 DSH（启动器调用的入口）。

    逻辑放这里而不是 `.cmd` 里：cmd 的解析与引号是另一套语言，踩过一次就够
    （LF 行尾）；Python 这边可单测、能给清楚的错误、还能回落到 `.env`。
    """
    for note in install(home, profile):
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
# 安装（渲染 + 接线检查；真正的 install_bundle 由 DSH 自己执行）
# ----------------------------------------------------------------------
def _profile_package(home: Path, profile: str) -> Path:
    return home / "profiles" / profile / "package.json"


def check_profile_wiring(home: Path, profile: str) -> list[str]:
    """这个 profile 认领了 presets bundle 吗（bundles 列表 + link 依赖 + 链接）。

    判据就是 `install_bundle` 实际改的那两处（2026-09-26 实测：它写 profile 的
    package.json，并建 `node_modules/<包名>` junction），所以检查与消费方一致。
    """
    pkg = _profile_package(home, profile)
    if not pkg.is_file():
        return [f"找不到 profile 清单：{pkg}（profile {profile!r} 尚未初始化？）"]
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"profile 清单解析失败：{exc}"]
    problems: list[str] = []
    bundles = ((data.get("dsh") or {}).get("profile") or {}).get("bundles") or []
    if bundle.BUNDLE_NAME not in bundles:
        problems.append(f"{profile} 的 dsh.profile.bundles 里没有 "
                        f"{bundle.BUNDLE_NAME}——该 profile 不会加载它")
    dep = str((data.get("dependencies") or {}).get(bundle.BUNDLE_NAME, ""))
    entry = home / "profiles" / profile / "node_modules" / bundle.BUNDLE_NAME
    if not dep:
        problems.append(f"{profile} 的 dependencies 里没有 {bundle.BUNDLE_NAME}；"
                        f"装法：plugin_manager → action: install_bundle → "
                        f"target={BUNDLE_DIR}")
    elif not entry.exists():
        problems.append(f"依赖声明了但模块链接不存在：{entry}"
                        f"（bundle 里的包自引用解析不到，preset 会 broken）")
    return problems


def runtime_dirs() -> list[Path]:
    """运行态检查要盯的目录：bundle 一份（旧版是三个安装副本）。"""
    return [BUNDLE_DIR]


def install(home: Path | None = None, profile: str = "desktop") -> list[str]:
    """渲染 bundle（幂等）+ 报告该 profile 的接线状态。

    安装本身**交给 DSH**：安装版随附文档写明 `install_bundle` 自己跑包安装与
    bundle 选择，并明确要求"不要用 shell 复现这些步骤"。
    """
    written = bundle.write_bundle()
    notes = [f"bundle 已渲染（{len(written)} 个文件）：{BUNDLE_DIR}"]
    notes.append(f"装法：plugin_manager → action: install_bundle → target: {BUNDLE_DIR}")
    if home is not None:
        notes += [f"[{profile}] {p}" for p in check_profile_wiring(home, profile)]
    return notes


# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python tools/dsh_install.py",
        description="同步并校验 Proteus 的 DSH 宿主接入")
    ap.add_argument("--home", default="", help="DSH home（缺省 $DSH_HOME 或 ~/.dsh）")
    ap.add_argument("--profile", default="web", help="启动器/bridge 用的 profile 名（缺省 web）")
    ap.add_argument("--presets-profile", default="desktop",
                    help="装载 presets bundle 的 profile（缺省 desktop；官方桌面端）")
    ap.add_argument("--roster-port", type=int, default=0,
                    help="查运行态 roster 的端口（缺省 0 = 依次试 19387/4080）")
    ap.add_argument("--check", action="store_true",
                    help="只检查，不改动（bundle 与来源不一致即非零退出）")
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
    print(f"DSH home : {home}")
    print(f"bundle   : {BUNDLE_DIR}")
    print(f"presets  : {', '.join(PRESET_IDS)}"
          f"（装载 profile：{args.presets_profile}）")

    if args.launch:
        return launch(args.profile, home, port=args.port)

    if not args.check:
        for note in install(home, args.presets_profile):
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
    problems += verify_bundle()
    problems += check_profile_wiring(home, args.presets_profile)
    problems += verify_patch()
    problems += verify_gate_consistency()
    problems += verify_launchers()
    if not args.no_bundle_check and args.profile == "web":
        # 独立的审计桥 bundle 只装在 web profile；桌面端由同一份 presets bundle 承载
        problems += check_bundle(home, args.profile)
        problems += check_bridge_entry(home, args.profile)
    notes: list[str] = []
    if not args.no_live:
        problems += live_check(args.profile, runtime_dirs())
        bridge_problems, bridge_live_note = bridge_live_check(
            Path(args.spool) if args.spool else REPO / "data" / "dsh-events.jsonl")
        problems += bridge_problems
        if bridge_live_note:
            notes.append(bridge_live_note)

    if not args.no_roster:
        ports = (args.roster_port,) if args.roster_port else ()
        roster_problems, roster_note = roster_live(home, ports)
        problems += roster_problems
        if roster_note:
            notes.append(roster_note)

    for note in notes:
        print(f"  · {note}")
    if problems:
        print(f"发现 {len(problems)} 个问题：")
        for p in problems:
            print(f"  ✗ {p}")
        if any("已过期" in p or "漂移" in p or "占位符" in p for p in problems):
            print("  → 重渲染：python tools/render_preset_bundle.py")
        if any("install_bundle" in p or "bundles 里没有" in p for p in problems):
            print(f"  → 装载：plugin_manager → action: install_bundle → "
                  f"target: {BUNDLE_DIR}")
        return 1
    print("接入健康：bundle 与 _shared/ 一致、三个声明齐全、"
          f"{args.presets_profile} 已接线"
          + ("、审计桥已接线且为链接" if args.profile == "web" else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
