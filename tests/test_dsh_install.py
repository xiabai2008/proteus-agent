"""DSH 接入工具测试：每一条校验都要能独立触发。

为什么值得测：这几条挡的都是**静默失效**——bundle 里声明行写错或插件行用了
`./x.mjs`，preset 就进不了选择器（界面零提示）；bundle 没重渲染就"跑旧代码"；
`!!js` 写错就求值成 `[object Object]`；profile 没登记 bundle 就整个不加载。
它们坏掉时不会有人报错。

2026-09-26 载体迁移后判据换了对象：不再查 `$DSH_HOME/.agent-presets/` 下的安装
副本（新版 DSH 已不读那个目录），改为查 **bundle 产物 + profile 接线 + 运行中
DSH 的 roster**——即消费方真正会读到的东西。
"""
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location("dsh_install",
                                               ROOT / "tools" / "dsh_install.py")
dsh_install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dsh_install)


def _junction(link: Path, target: Path) -> bool:
    """建 Windows junction（测试用；非 Windows 或无权限时返回 False）。"""
    if sys.platform != "win32":
        return False
    proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                          capture_output=True, text=True, check=False)
    return proc.returncode == 0 and link.exists()


def _fake_bundle(tmp_path: Path, patch_body: str,
                 exports: dict | None = None) -> Path:
    """造一个最小 bundle 目录（声明行 + package.json）。"""
    dst = tmp_path / "bundle"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "cordis.patch.yml").write_text(patch_body, encoding="utf-8")
    (dst / "package.json").write_text(json.dumps({
        "name": dsh_install.bundle.BUNDLE_NAME,
        "exports": exports if exports is not None else {
            f"./{key}": f"./{name}"
            for name, key in dsh_install.bundle.SHARED_FILES.items()},
        "dsh": {"bundle": {"patch": "./cordis.patch.yml"}},
    }, ensure_ascii=False), encoding="utf-8")
    return dst


def _decl_problems(problems: list[str]) -> list[str]:
    """只保留**声明行写法**类问题（滤掉产物同步类：那是另一个用例的活）。

    `_fake_bundle` 造的补丁必然与渲染结果不同，所以 `bundle_problems` 一定会报
    "缺少/已过期"——本组用例只关心声明行能不能被读懂。
    """
    noise = ("缺少", "已过期", "漂移")
    return [p for p in problems if not any(n in p for n in noise)]


def _decl(preset_id: str, plugins: str = "") -> str:
    return (f"    - id: preset-{preset_id}\n"
            f"      name: '@deepseek-ai/dsh-agent-preset'\n"
            f"      config:\n"
            f"        id: {preset_id}\n"
            f"        plugins:\n{plugins}")


def _all_declarations(plugins: str = "          - id: persona\n"
                                     "            name: "
                                     "'@deepseek-ai/dsh-persona'\n") -> str:
    return ("- insert:\n"
            + "".join(_decl(pid, plugins) for pid in dsh_install.PRESET_IDS))


# ----------------------------------------------------------------------
# 结构校验：bundle 自身
# ----------------------------------------------------------------------
def test_repo_bundle_passes_verification():
    """仓库当前状态必须过检（回归锁）：三个声明 + 无相对行 + exports 齐全。"""
    assert dsh_install.verify_bundle() == []


def test_verify_accepts_bare_package_rows(tmp_path):
    """裸包名行不做本地存在性检查——那是运行中 roster 的活。"""
    dst = _fake_bundle(tmp_path, _all_declarations())
    assert _decl_problems(dsh_install.verify_bundle(dst)) == []


def test_verify_flags_relative_plugin_row(tmp_path):
    """`./x.mjs` = 必然 broken（实测：相对基准是 profile 目录，不是 bundle 目录）。"""
    plugins = ("          - id: persona\n"
               "            name: './proteus-persona.mjs'\n")
    dst = _fake_bundle(tmp_path, _all_declarations(plugins))
    problems = dsh_install.verify_bundle(dst)
    assert any("相对 specifier" in p and "proteus-persona.mjs" in p
               for p in problems), problems
    assert any("包自引用" in p for p in problems), problems


def test_verify_flags_js_expression_with_colon(tmp_path):
    """`!!js` 尾部出现 ': ' 会被 YAML 拆成映射键（指南实测的坑）。"""
    plugins = ("          - id: mcp\n"
               "            name: '@deepseek-ai/dsh-mcp-client'\n"
               "            config:\n"
               "              command: !!js (process.env.A || 'python') + '/x'\n"
               "              bad: !!js (process.env.A ? '/x' : '/y')\n")
    dst = _fake_bundle(tmp_path, _all_declarations(plugins))
    problems = dsh_install.verify_bundle(dst)
    assert any("!!js" in p and "': '" in p for p in problems), problems


def test_verify_does_not_flag_comment_mentioning_the_pitfall(tmp_path):
    """注释里写这个坑（含 ': ' 字样）不能被误报——bundle 里就有这样的注释。"""
    body = ("# 注意：!!js 整行禁止出现 \": \"（冒号+空格会被 YAML 拆成映射键）\n"
            + _all_declarations())
    dst = _fake_bundle(tmp_path, body)
    assert _decl_problems(dsh_install.verify_bundle(dst)) == []


def test_verify_flags_missing_declaration(tmp_path):
    """少一个声明行 = 选择器里少一个入口，且没有任何提示。"""
    only_two = "- insert:\n" + "".join(
        _decl(pid, "          - id: p\n            name: '@x/y'\n")
        for pid in dsh_install.PRESET_IDS[:2])
    dst = _fake_bundle(tmp_path, only_two)
    problems = dsh_install.verify_bundle(dst)
    assert any(dsh_install.PRESET_IDS[2] in p and "缺声明行" in p
               for p in problems), problems


def test_verify_flags_missing_export(tmp_path):
    """exports 缺一项 -> 包自引用解析不到 -> preset broken。"""
    dst = _fake_bundle(tmp_path, _all_declarations(),
                       exports={"./package.json": "./package.json"})
    problems = dsh_install.verify_bundle(dst)
    assert any("exports 缺" in p for p in problems), problems


def test_bundle_problems_reports_missing_dir(tmp_path):
    problems = dsh_install.bundle_problems(tmp_path / "nope")
    assert problems and "不存在" in problems[0]


def test_verify_patch_requires_all_three_tiers(tmp_path):
    patch = tmp_path / "patch.yml"
    patch.write_text("proteus-safe\nproteus-standard\n", encoding="utf-8")
    problems = dsh_install.verify_patch(patch)
    assert any("proteus-ctf" in p for p in problems)
    assert not any("proteus-safe" in p for p in problems)

    patch.write_text("proteus-safe\nproteus-standard\nproteus-ctf\n",
                     encoding="utf-8")
    assert dsh_install.verify_patch(patch) == []


# ----------------------------------------------------------------------
# profile 接线：bundle 是否被这个 profile 认领
# ----------------------------------------------------------------------
def test_check_profile_wiring_reports_missing_profile(tmp_path):
    problems = dsh_install.check_profile_wiring(tmp_path / "dsh", "desktop")
    assert problems and "找不到 profile 清单" in problems[0]


def test_check_profile_wiring_reports_missing_registration(tmp_path):
    home = tmp_path / "dsh"
    profile = home / "profiles" / "desktop"
    profile.mkdir(parents=True)
    (profile / "package.json").write_text(
        json.dumps({"dependencies": {}, "dsh": {"profile": {"bundles": []}}}),
        encoding="utf-8")

    problems = dsh_install.check_profile_wiring(home, "desktop")
    assert any("bundles 里没有" in p for p in problems), problems
    assert any("dependencies 里没有" in p for p in problems), problems
    assert any("install_bundle" in p for p in problems)      # 给出官方装法


def test_check_profile_wiring_accepts_wired_profile(tmp_path):
    home = tmp_path / "dsh"
    profile = home / "profiles" / "desktop"
    (profile / "node_modules").mkdir(parents=True)
    (profile / "package.json").write_text(json.dumps({
        "dependencies": {dsh_install.bundle.BUNDLE_NAME: "link:D:/ws/x"},
        "dsh": {"profile": {"bundles": [dsh_install.bundle.BUNDLE_NAME]}},
    }), encoding="utf-8")
    (profile / "node_modules" / dsh_install.bundle.BUNDLE_NAME).mkdir()
    assert dsh_install.check_profile_wiring(home, "desktop") == []


def test_check_profile_wiring_flags_missing_module_link(tmp_path):
    home = tmp_path / "dsh"
    profile = home / "profiles" / "desktop"
    profile.mkdir(parents=True)
    (profile / "package.json").write_text(json.dumps({
        "dependencies": {dsh_install.bundle.BUNDLE_NAME: "link:D:/ws/x"},
        "dsh": {"profile": {"bundles": [dsh_install.bundle.BUNDLE_NAME]}},
    }), encoding="utf-8")
    problems = dsh_install.check_profile_wiring(home, "desktop")
    assert any("模块链接不存在" in p for p in problems), problems


# ----------------------------------------------------------------------
# 运行态 roster：判据落在**运行中的 DSH**（消费方视角）
# ----------------------------------------------------------------------
def test_roster_live_skips_without_credentials(tmp_path):
    problems, note = dsh_install.roster_live(tmp_path, (1,))
    assert problems == [] and "跳过" in note


def test_roster_live_flags_missing_and_broken(tmp_path, monkeypatch):
    def _fake_rpc(home, port, method, args=None):
        return {"result": {"value": {"presets": [
            {"id": "standard", "isDefault": True},
            {"id": "proteus-pentest", "broken": "persona (./x.mjs): never started"},
        ]}}}, ""

    monkeypatch.setattr(dsh_install, "rpc_call", _fake_rpc)
    problems, _ = dsh_install.roster_live(tmp_path, (1234,))
    joined = "\n".join(problems)
    assert "proteus-ctf-web" in joined and "roster 里没有" in joined
    assert "broken" in joined and "proteus-pentest" in joined


def test_roster_live_ok_when_all_present(tmp_path, monkeypatch):
    monkeypatch.setattr(dsh_install, "rpc_call", lambda *a, **k: ({
        "result": {"value": {"presets": [
            {"id": pid, "isDefault": False} for pid in dsh_install.PRESET_IDS
        ]}}}, ""))
    problems, note = dsh_install.roster_live(tmp_path, (1234,))
    assert problems == [] and "roster OK" in note


def test_rpc_cookie_needs_browser_session_secret(tmp_path):
    assert dsh_install._rpc_cookie(tmp_path, "http://127.0.0.1:1") is None
    (tmp_path / ".credentials.yaml").write_text("other: x\n", encoding="utf-8")
    assert dsh_install._rpc_cookie(tmp_path, "http://127.0.0.1:1") is None

    (tmp_path / ".credentials.yaml").write_text(
        "client-connection/browser-session:\n  secret: abc-_def\n",
        encoding="utf-8")
    cookie = dsh_install._rpc_cookie(tmp_path, "http://127.0.0.1:1")
    assert cookie and cookie.startswith("dsh-auth-") and cookie.count(".") == 2


# ----------------------------------------------------------------------
# 运行态：改了的代码在**正在跑的进程**里生效了吗（Node 的 ESM 缓存不重启不更新）
# ----------------------------------------------------------------------
def test_live_check_flags_process_older_than_bundle_files(monkeypatch):
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: [
        {"pid": 25904, "start": "2020-01-01T00:00:00", "cmd": "x"}])
    problems = dsh_install.live_check("web", dsh_install.runtime_dirs())
    assert len(problems) == 1
    assert "pid=25904" in problems[0] and "ESM 缓存" in problems[0]


def test_live_check_passes_when_process_started_after_files(monkeypatch):
    import datetime

    future = (datetime.datetime.now() + datetime.timedelta(minutes=1)).isoformat()
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: [
        {"pid": 1, "start": future, "cmd": "x"}])
    assert dsh_install.live_check("web", dsh_install.runtime_dirs()) == []


def test_live_check_skips_without_running_process(tmp_path, monkeypatch):
    """没在跑就跳过——这条检查不该在"只装不跑"的场景下报错。"""
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: [])
    assert dsh_install.live_check("web", [tmp_path]) == []


def test_verify_launcher_flags_lf_only_cmd(tmp_path):
    """LF-only 的 .cmd 会被 cmd.exe 拼错——这条把它钉成 CRLF。

    实测（2026-09-23）：同内容 LF 下 11 行乱码报错（`'T_WS' 不是内部或外部命令`），
    CRLF 下正常。用户看到的就是"双击了没反应"。
    """
    p = tmp_path / "x.cmd"
    p.write_bytes(b"@echo off\nrem hi\necho ok\n")
    problems = dsh_install.verify_launcher(p)
    assert len(problems) == 1 and "CRLF" in problems[0]

    p.write_bytes(b"@echo off\r\nrem hi\r\necho ok\r\n")
    assert dsh_install.verify_launcher(p) == []


def test_repo_launcher_is_crlf():
    """仓库里**所有** .cmd 启动器都必须过检——否则用户双击就是"没反应"。"""
    assert dsh_install.verify_launchers() == []


def test_env_file_value_and_workspace_root(tmp_path, monkeypatch):
    """`.env` 回落：双击场景下环境变量可能没继承到，不能再强依赖它。"""
    (tmp_path / ".env").write_text("PENTEST_WS=D:/ws\nPENTEST_PY312=D:/py\n",
                                   encoding="utf-8")
    monkeypatch.setattr(dsh_install, "REPO", tmp_path)
    assert dsh_install._env_file_value("PENTEST_WS") == "D:/ws"
    assert dsh_install._env_file_value("NOPE") == ""

    monkeypatch.delenv("PENTEST_WS", raising=False)
    assert dsh_install.workspace_root() == Path("D:/ws")
    monkeypatch.setenv("PENTEST_WS", str(tmp_path / "env-wins"))
    assert dsh_install.workspace_root() == tmp_path / "env-wins"


def test_port_in_use_detects_listener():
    import socket

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert dsh_install.port_in_use(port) is True
    finally:
        srv.close()
    assert dsh_install.port_in_use(port) is False


def test_port_owner_pids_parses_netstat(monkeypatch):
    """端口占用者从 `netstat -ano` 解析（不依赖 PowerShell——它可能不在 PATH 上）。"""
    sample = (
        "  TCP    127.0.0.1:4080         0.0.0.0:0              LISTENING       48332\n"
        "  TCP    127.0.0.1:9999         0.0.0.0:0              LISTENING       1234\n"
        "  TCP    127.0.0.1:4080         127.0.0.1:5555         ESTABLISHED     48332\n")

    class _Proc:
        stdout = sample

    monkeypatch.setattr(dsh_install, "_system_exe", lambda name, subdir="": "netstat")
    monkeypatch.setattr(dsh_install.subprocess, "run", lambda *a, **k: _Proc())
    assert dsh_install.port_owner_pids(4080) == [48332]


def test_wait_port_free_times_out_when_still_listening(monkeypatch):
    monkeypatch.setattr(dsh_install, "port_in_use",
                        lambda port, host="127.0.0.1": True)
    assert dsh_install.wait_port_free(4080, timeout=0.1) is False


@pytest.mark.skipif(sys.platform != "win32",
                    reason="node.exe 定位是 Windows 语义（ProgramFiles 布局）")
def test_system_exe_finds_node_without_path(monkeypatch, tmp_path):
    """最小环境（PATH 里没有 node）也要能定位 node.exe。

    实测：双击启动器的环境可能残缺，只靠 `shutil.which` 会拿到空串，
    然后 subprocess 抛未捕获的 FileNotFoundError。
    """
    (tmp_path / "nodejs").mkdir()
    (tmp_path / "nodejs" / "node.exe").write_text("x", encoding="utf-8")
    monkeypatch.setattr(dsh_install.shutil, "which", lambda name: None)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    assert dsh_install._system_exe("node").endswith("node.exe")


def test_is_dsh_cmdline_accepts_both_launch_shapes():
    """两种启动姿势都要认——只认前一种会让运行态检查**静默跳过**。

    实测（2026-09-23）：用户从源码起的是 `bin.ts "web"`，命令行里没有
    `--profile web`，于是检查"通过"了却什么都没查。
    """
    launcher = ('"C:\\Program Files\\nodejs\\node.exe" apps/cli/lib/bin.js '
                '--profile web --patch D:/x/dsh/proteus.cordis.patch.yml --no-open')
    devmode = 'node  --import tsx/esm apps/cli/src/bin.ts "web"'
    other_profile = ('node apps/cli/lib/bin.js --profile headless')
    other_dev = 'node --import tsx/esm apps/cli/src/bin.ts "headless"'

    # 用合成路径：本用例也在 test_path_hygiene 的扫描范围内，不能写真实工作区路径
    real = ('"C:\\Program Files\\nodejs\\node.EXE" '
            'D:\\ws\\deepseek-harness\\apps\\cli\\lib\\bin.js '
            '--profile web --patch D:\\ws\\proteus-agent\\dsh\\proteus.cordis.patch.yml')
    assert dsh_install._is_dsh_cmdline(real, "web") is True      # 真实启动器的形态
    assert dsh_install._is_dsh_cmdline(launcher, "web") is True
    assert dsh_install._is_dsh_cmdline(devmode, "web") is True
    assert dsh_install._is_dsh_cmdline(other_profile, "web") is False
    assert dsh_install._is_dsh_cmdline(other_dev, "web") is False
    assert dsh_install._is_dsh_cmdline("", "web") is False
    assert dsh_install._is_dsh_cmdline("notepad.exe web", "web") is False


def test_bridge_live_check_reads_spool_ownership(tmp_path):
    """审计桥活体判据：spool 最新记录有没有 preset 字段（与怎么启动无关）。"""
    spool = tmp_path / "dsh-events.jsonl"
    # 老代码写的记录（没有 preset 字段）
    spool.write_text('{"kind":"call","tool":"pwsh"}\n' * 3, encoding="utf-8")
    problems, _ = dsh_install.bridge_live_check(spool)
    assert len(problems) == 1 and "旧代码" in problems[0]

    # 新代码写的记录（带 preset）
    spool.write_text('{"kind":"call","tool":"pwsh"}\n'
                     '{"kind":"call","tool":"pwsh","preset":"proteus"}\n',
                     encoding="utf-8")
    problems, note = dsh_install.bridge_live_check(spool)
    assert problems == [] and "当前代码" in note


def test_bridge_live_check_skips_when_no_spool(tmp_path):
    problems, note = dsh_install.bridge_live_check(tmp_path / "nope.jsonl")
    assert problems == [] and "暂无 spool" in note


def test_bridge_live_check_skips_unparseable_spool(tmp_path):
    spool = tmp_path / "x.jsonl"
    spool.write_text("not json\n", encoding="utf-8")
    problems, note = dsh_install.bridge_live_check(spool)
    assert problems == [] and "没有可解析记录" in note


def test_parse_start_handles_net_and_garbage():
    assert dsh_install._parse_start("not-a-date") == 0.0
    assert dsh_install._parse_start("") == 0.0
    # .NET 的 'o'：7 位小数 + 偏移，必须能解析（截到秒的退化路径）
    assert dsh_install._parse_start("2026-09-22T10:20:44.1234567+08:00") > 0
    assert dsh_install._parse_start("2026-09-22T10:20:44") > 0


# ----------------------------------------------------------------------
# main：出问题要非零退出，并给出**可执行**的修复指引
# ----------------------------------------------------------------------
def test_check_fails_when_bundle_out_of_sync(monkeypatch, capsys):
    monkeypatch.setattr(dsh_install, "verify_bundle",
                        lambda *a, **k: ["cordis.patch.yml 已过期（来源改了但没重渲染）"])
    monkeypatch.setattr(dsh_install, "verify_launcher", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "verify_patch", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "verify_gate_consistency", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "check_profile_wiring", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "roster_live",
                        lambda *a, **k: ([], "跳过 roster 检查"))

    rc = dsh_install.main(["--check", "--no-live", "--no-bundle-check",
                           "--home", str(ROOT)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "已过期" in out
    assert "render_preset_bundle.py" in out          # 给出修复命令


def test_check_reports_roster_note(monkeypatch, capsys):
    monkeypatch.setattr(dsh_install, "verify_bundle", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "verify_launcher", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "verify_patch", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "verify_gate_consistency", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "check_profile_wiring", lambda *a, **k: [])
    monkeypatch.setattr(dsh_install, "roster_live",
                        lambda *a, **k: ([], "roster OK（7 个 preset）"))

    rc = dsh_install.main(["--check", "--no-live", "--no-bundle-check",
                           "--home", str(ROOT)])
    out = capsys.readouterr().out
    assert rc == 0 and "roster OK" in out and "接入健康" in out


# ----------------------------------------------------------------------
# --restart：已有实例在跑时，双击启动器必须真的重启（而不是起一个注定失败的第二实例）
# ----------------------------------------------------------------------
def _stub_running(monkeypatch, procs):
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: procs)


def _stub_checks(monkeypatch):
    """把与 --restart 无关的检查全部置空（跑的是重启流程，不是体检）。"""
    for name in ("verify_bundle", "verify_patch", "verify_gate_consistency",
                 "verify_launcher", "check_profile_wiring"):
        monkeypatch.setattr(dsh_install, name, lambda *a, **k: [])


def test_restart_aborts_when_ask_declined(tmp_path, monkeypatch, capsys):
    """`--ask` 且拿不到确认时不能关进程；但必须明说"什么都没做"。"""
    _stub_running(monkeypatch, [{"pid": 25904, "start": "", "cmd": ""}])
    _stub_checks(monkeypatch)
    killed: list = []
    monkeypatch.setattr(dsh_install, "terminate_dsh",
                        lambda procs: killed.append(procs) or [])
    monkeypatch.setattr(dsh_install.sys, "stdin", io.StringIO(""))  # isatty() = False

    rc = dsh_install.main(["--home", str(tmp_path), "--restart", "--ask",
                           "--check", "--no-roster", "--no-live",
                           "--no-bundle-check"])
    out = capsys.readouterr().out
    assert rc == 1 and killed == []
    assert "EADDRINUSE" in out and "已取消" in out


def test_confirm_never_raises_on_broken_stdin(monkeypatch):
    """stdin 读不到时必须返回 False，而不是把启动流程崩掉。

    实测教训：双击启动器那次就是 `input()` 抛 EOFError、整个流程崩栈——
    重启没发生，人还以为发生了。
    """
    monkeypatch.setattr(dsh_install.sys, "stdin", io.StringIO(""))
    assert dsh_install._confirm() is False

    class _Tty:
        def isatty(self):
            return True

    monkeypatch.setattr(dsh_install.sys, "stdin", _Tty())

    def _boom(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", _boom)
    assert dsh_install._confirm() is False


def test_restart_kills_then_continues(tmp_path, monkeypatch, capsys):
    _stub_running(monkeypatch, [{"pid": 1, "start": "", "cmd": ""}])
    _stub_checks(monkeypatch)
    killed: list = []
    monkeypatch.setattr(dsh_install, "terminate_dsh",
                        lambda procs: killed.append(procs) or ["已结束 DSH 进程 pid=1"])
    monkeypatch.setattr(dsh_install, "wait_gone",
                        lambda procs, profile="web", timeout=15.0: True)

    # 默认**不问**：双击启动器就是"启动"的明确意图，问一句只会多一个失败点
    rc = dsh_install.main(["--home", str(tmp_path), "--restart", "--check",
                           "--no-roster", "--no-live", "--no-bundle-check"])
    out = capsys.readouterr().out
    assert rc == 0 and len(killed) == 1
    assert "端口已释放" in out


def test_restart_is_noop_without_running_instance(tmp_path, monkeypatch):
    _stub_running(monkeypatch, [])
    _stub_checks(monkeypatch)
    killed: list = []
    monkeypatch.setattr(dsh_install, "terminate_dsh",
                        lambda procs: killed.append(procs) or [])

    rc = dsh_install.main(["--home", str(tmp_path), "--restart", "--check",
                           "--no-roster", "--no-live", "--no-bundle-check"])
    assert rc == 0 and killed == []


def test_restart_stops_if_process_survives(tmp_path, monkeypatch, capsys):
    """杀了但没退出：必须停住报错，绝不能接着起第二个实例（又会撞端口）。"""
    _stub_running(monkeypatch, [{"pid": 1, "start": "", "cmd": ""}])
    _stub_checks(monkeypatch)
    monkeypatch.setattr(dsh_install, "terminate_dsh", lambda procs: ["killed"])
    monkeypatch.setattr(dsh_install, "wait_gone",
                        lambda procs, profile="web", timeout=15.0: False)

    rc = dsh_install.main(["--home", str(tmp_path), "--restart", "--check",
                           "--no-roster", "--no-live", "--no-bundle-check"])
    out = capsys.readouterr().out
    assert rc == 1 and "未在 15 秒内退出" in out


# ----------------------------------------------------------------------
# R-13：内层 ask 档被抬起时，外层必须还有"会问人"的档位
# ----------------------------------------------------------------------
def _preset_with_args(tmp_path, args: list[str]) -> Path:
    p = tmp_path / "agent.cordis.yml"
    p.write_text("- id: mcp-proteus\n  name: '@deepseek-ai/dsh-mcp-client'\n"
                 f"  config:\n    args: {args}\n",
                 encoding="utf-8")
    return p


def test_gate_consistency_flags_lifted_ask_without_human_gate(tmp_path):
    """`--authorize` + 三档全 never = DSH 会话没有任何人工确认环节。"""
    preset = _preset_with_args(
        tmp_path, ["-m", "penagent", "mcp", "--authorize", "--default-mode",
                   "pentest-standard"])
    patch = tmp_path / "patch.yml"
    patch.write_text("proteus-safe:\n  sandbox: read-only\n  approval: never\n"
                     "proteus-standard:\n  approval: never\n",
                     encoding="utf-8")

    problems = dsh_install.verify_gate_consistency(preset, patch)
    assert len(problems) == 1 and "approval: ask" in problems[0]


def test_gate_consistency_ok_when_one_tier_asks(tmp_path):
    preset = _preset_with_args(tmp_path, ["--authorize"])
    patch = tmp_path / "patch.yml"
    patch.write_text("proteus-safe:\n  approval: ask\n"
                     "proteus-ctf:\n  approval: never\n", encoding="utf-8")
    assert dsh_install.verify_gate_consistency(preset, patch) == []


def test_gate_consistency_ignores_preset_without_authorize(tmp_path):
    """没抬起内层 ask 档时，外层怎么配都不归这条管。"""
    preset = _preset_with_args(tmp_path, ["-m", "penagent", "mcp"])
    patch = tmp_path / "patch.yml"
    patch.write_text("approval: never\n", encoding="utf-8")
    assert dsh_install.verify_gate_consistency(preset, patch) == []


def test_repo_gate_consistency_holds():
    """仓库当前状态必须过检（回归锁）：bundle 里带 --authorize，补丁里三档含 ask。

    这条同时钉住"bundle 补丁的嵌套结构也读得到 args"——声明行在 `insert` 之下、
    MCP 行又在 `config.plugins` 之下，平铺读顶层行会漏掉它（那样这条检查会永远
    "通过"，等于没有）。
    """
    assert dsh_install.verify_gate_consistency() == []


def test_gate_consistency_reads_nested_bundle_rows(tmp_path):
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "cordis.patch.yml").write_text(
        "- insert:\n"
        "    - id: preset-x\n"
        "      name: '@deepseek-ai/dsh-agent-preset'\n"
        "      config:\n"
        "        id: x\n"
        "        plugins:\n"
        "          - id: mcp-proteus\n"
        "            name: '@deepseek-ai/dsh-mcp-client'\n"
        "            config:\n"
        "              args: ['-m', 'penagent', '--authorize']\n",
        encoding="utf-8")
    patch = tmp_path / "patch.yml"
    patch.write_text("proteus-ctf:\n  approval: never\n", encoding="utf-8")
    problems = dsh_install.verify_gate_consistency(
        bundle_dir / "cordis.patch.yml", patch)
    assert len(problems) == 1 and "approval: ask" in problems[0]


# ----------------------------------------------------------------------
# 审计桥接线（web profile 的独立 bundle）
# ----------------------------------------------------------------------
def test_check_bundle_reports_missing_wiring(tmp_path):
    home = tmp_path / "dsh"
    web = home / "profiles" / "web"
    web.mkdir(parents=True)
    (web / "package.json").write_text(json.dumps({"dependencies": {}}),
                                      encoding="utf-8")
    problems = dsh_install.check_bundle(home, "web")
    assert any("依赖里没有" in p for p in problems)
    assert any("bundles 里没有" in p for p in problems)
    assert any("dsh plugin" in p for p in problems)   # 给官方装法

    (web / "package.json").write_text(json.dumps({
        "dependencies": {dsh_install.BRIDGE_NAME: "link:..."},
        "dsh": {"profile": {"bundles": [dsh_install.BRIDGE_NAME]}},
    }), encoding="utf-8")
    assert dsh_install.check_bundle(home, "web") == []


def test_check_bundle_reports_missing_profile(tmp_path):
    assert dsh_install.check_bundle(tmp_path / "dsh", "web")


def test_check_bridge_entry_flags_plain_directory(tmp_path):
    """普通目录 = 旧副本（实测：09-21 的副本让审计层跑了两天前的代码）。"""
    home = tmp_path / "dsh"
    entry = home / "profiles" / "web" / "node_modules" / dsh_install.BRIDGE_NAME
    entry.mkdir(parents=True)
    problems = dsh_install.check_bridge_entry(home, "web")
    assert any("普通目录" in p for p in problems), problems


def test_check_bridge_entry_accepts_link(tmp_path):
    home = tmp_path / "dsh"
    entry = home / "profiles" / "web" / "node_modules" / dsh_install.BRIDGE_NAME
    entry.parent.mkdir(parents=True)
    src = tmp_path / "bridge-src"
    src.mkdir()
    if not _junction(entry, src):
        pytest.skip("本机建不了 junction，跳过链接用例")
    assert dsh_install.check_bridge_entry(home, "web") == []


def test_check_bridge_entry_reports_missing(tmp_path):
    problems = dsh_install.check_bridge_entry(tmp_path / "dsh", "web")
    assert any("不存在" in p for p in problems)


def test_shared_implementation_has_a_single_source():
    """共享实现只允许在 `_shared/` 有一份——拷贝必然漂移。

    bundle 里的四份是**逐字节副本**（Node 的 exports 不允许指向包外），
    由 test_preset_bundle.py 钉住不漂移；模式目录本身不得自带 .mjs。
    """
    shared = ROOT / "dsh" / ".agent-presets" / "_shared"
    for name in dsh_install.SHARED_FILES:
        assert (shared / name).is_file(), name
    for preset_id in dsh_install.PRESETS:
        preset_dir = ROOT / "dsh" / ".agent-presets" / preset_id
        copies = [p.name for p in preset_dir.iterdir() if p.suffix == ".mjs"]
        assert copies == [], f"{preset_id} 不应自带 .mjs 拷贝：{copies}"
