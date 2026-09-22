"""DSH 接入同步器测试：每一条校验都要能独立触发。

为什么值得测：这几条挡的都是**静默失效**——preset 少一个文件就整份从选择器里
消失、安装副本过期就"跑旧代码"而毫无提示（实测踩中过：当天下午写的守卫因为
副本停在上午而根本没上线）、`!!js` 写错就求值成 `[object Object]`、审计桥是
普通目录副本就说明它不是仓库当前代码。它们坏掉时不会有人报错。
"""
import importlib.util
import json
import shutil
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


def _preset_dir(tmp_path: Path, body: str) -> Path:
    dst = tmp_path / "proteus"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "agent.cordis.yml").write_text(body, encoding="utf-8")
    (dst / "preset.yml").write_text("name: t\n", encoding="utf-8")
    return dst


def _junction(link: Path, target: Path) -> bool:
    """建 Windows junction（测试用；非 Windows 或无权限时返回 False）。"""
    if sys.platform != "win32":
        return False
    proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                          capture_output=True, text=True, check=False)
    return proc.returncode == 0 and link.exists()


# ----------------------------------------------------------------------
# 结构校验
# ----------------------------------------------------------------------
def test_verify_accepts_installed_package_rows(tmp_path):
    """包名行（@deepseek-ai/…）不做本地存在性检查——那是 roster 的活。"""
    dst = _preset_dir(tmp_path, "- id: a\n  name: '@deepseek-ai/dsh-persona'\n")
    assert dsh_install.verify_preset(dst) == []


def test_verify_flags_missing_relative_plugin(tmp_path):
    """相对 specifier 解析不到 = 整份 preset broken（最贵的一种静默失效）。"""
    dst = _preset_dir(
        tmp_path,
        "- id: policy\n  name: './proteus-tools-policy.mjs'\n  config:\n    role: policy\n")
    problems = dsh_install.verify_preset(dst)
    assert any("相对 specifier" in p and "proteus-tools-policy.mjs" in p
               for p in problems), problems

    (dst / "proteus-tools-policy.mjs").write_text("export function apply() {}\n",
                                                  encoding="utf-8")
    assert dsh_install.verify_preset(dst) == []


def test_verify_flags_missing_required_file(tmp_path):
    dst = _preset_dir(tmp_path, "- id: a\n  name: '@deepseek-ai/dsh-persona'\n")
    (dst / "preset.yml").unlink()
    assert any("preset.yml" in p for p in dsh_install.verify_preset(dst))


def test_verify_flags_js_expression_with_colon(tmp_path):
    """`!!js` 尾部出现 ': ' 会被 YAML 拆成映射键（指南实测的坑）。"""
    dst = _preset_dir(
        tmp_path,
        "- id: mcp\n  name: '@deepseek-ai/dsh-mcp-client'\n"
        "  config:\n"
        "    command: !!js (process.env.A || 'python') + '/python.exe'\n"
        "    bad: !!js (process.env.A ? '/x' : '/y')\n")
    problems = dsh_install.verify_preset(dst)
    assert any("!!js" in p and "': '" in p for p in problems), problems


def test_verify_does_not_flag_comment_mentioning_the_pitfall(tmp_path):
    """注释里写这个坑（含 ': ' 字样）不能被误报——preset 里就有这样的注释。"""
    dst = _preset_dir(
        tmp_path,
        "# 注意：!!js 整行禁止出现 \": \"（冒号+空格会被 YAML 拆成映射键）\n"
        "- id: a\n  name: '@deepseek-ai/dsh-persona'\n")
    assert dsh_install.verify_preset(dst) == []


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
# 漂移：跑旧代码的唯一可靠判据
# ----------------------------------------------------------------------
def test_drift_detects_stale_and_missing_files(tmp_path):
    dst = tmp_path / "installed"
    dst.mkdir()
    for name in ("agent.cordis.yml", "preset.yml"):
        (dst / name).write_text("old\n", encoding="utf-8")

    problems = dsh_install.drift(dst)
    # 四个源文件全都不一致：两个内容不同、两个缺失
    assert len(problems) == 4, problems
    assert any("已过期" in p for p in problems)
    assert any("缺少" in p for p in problems)


def test_drift_reports_missing_directory(tmp_path):
    assert "不存在" in dsh_install.drift(tmp_path / "nope")[0]


def test_install_syncs_and_is_idempotent(tmp_path):
    home = tmp_path / "dsh"
    notes = dsh_install.install(home)
    assert any("已同步" in n for n in notes), notes
    dst = home / ".agent-presets" / "proteus"
    assert dsh_install.drift(dst) == []
    assert dsh_install.verify_preset(dst) == []

    again = dsh_install.install(home)
    assert any("已是最新" in n for n in again), again


def test_install_replaces_a_link_with_a_real_directory(tmp_path):
    """链接必须被摘掉：DSH 的发现机制不跟随 reparse point（实测 COUNT 2→1）。

    摘链接用 `cmd rmdir`——PowerShell / Path.unlink 对 junction 有递归删目标的风险，
    所以这条同时断言**目标文件还在**。
    """
    home = tmp_path / "dsh"
    dst = home / ".agent-presets" / "proteus"
    dst.parent.mkdir(parents=True)
    src = tmp_path / "real"
    src.mkdir()
    (src / "keep.txt").write_text("target must survive\n", encoding="utf-8")
    if not _junction(dst, src):
        pytest.skip("本机建不了 junction，跳过链接替换用例")

    notes = dsh_install.install(home)
    assert any("移除原有链接" in n for n in notes), notes
    assert not dsh_install._is_reparse_point(dst)
    assert (src / "keep.txt").is_file(), "摘链接时把目标内容删了"
    assert dsh_install.drift(dst) == []


def test_backup_lives_outside_the_preset_root(tmp_path):
    """备份不能放在 preset 根目录里——那会被发现机制当成一个 preset。"""
    home = tmp_path / "dsh"
    dst = home / ".agent-presets" / "proteus"
    dst.mkdir(parents=True)
    (dst / "agent.cordis.yml").write_text("stale\n", encoding="utf-8")
    (dst / "preset.yml").write_text("stale\n", encoding="utf-8")

    dsh_install.install(home)
    backups = list((home / "backups").glob("preset-proteus-*"))
    assert len(backups) == 1
    assert (backups[0] / "agent.cordis.yml").read_text(encoding="utf-8") == "stale\n"
    # preset 根里只应有 proteus 这一个目录
    assert [p.name for p in (home / ".agent-presets").iterdir()] == ["proteus"]


def test_backup_keeps_only_the_newest_three(tmp_path):
    home = tmp_path / "dsh"
    dsh_install.install(home)
    dst = home / ".agent-presets" / "proteus"
    for i in range(5):
        (dst / "preset.yml").write_text(f"v{i}\n", encoding="utf-8")
        dsh_install.install(home)
    assert len(list((home / "backups").glob("preset-proteus-*"))) <= 3


def test_check_fails_on_drift(tmp_path, capsys):
    home = tmp_path / "dsh"
    dsh_install.install(home)
    dst = home / ".agent-presets" / "proteus"
    (dst / "proteus-tools-policy.mjs").write_text("// stale\n", encoding="utf-8")

    rc = dsh_install.main(["--home", str(home), "--check", "--no-roster",
                           "--no-bundle-check"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "与仓库不同步" in out and "已过期" in out
    assert "python tools/dsh_install.py" in out      # 给出修复命令


# ----------------------------------------------------------------------
# 运行态：改了的代码在**正在跑的进程**里生效了吗（Node 的 ESM 缓存不重启不更新）
# ----------------------------------------------------------------------
def test_live_check_flags_process_older_than_installed_files(tmp_path, monkeypatch):
    home = tmp_path / "dsh"
    dsh_install.install(home)
    dst = home / ".agent-presets" / "proteus"
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: [
        {"pid": 25904, "start": "2020-01-01T00:00:00", "cmd": "x"}])

    problems = dsh_install.live_check("web", dst)
    assert len(problems) == 1
    assert "pid=25904" in problems[0] and "ESM 缓存" in problems[0]


def test_live_check_passes_when_process_started_after_files(tmp_path, monkeypatch):
    import datetime

    home = tmp_path / "dsh"
    dsh_install.install(home)
    dst = home / ".agent-presets" / "proteus"
    future = (datetime.datetime.now() + datetime.timedelta(minutes=1)).isoformat()
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: [
        {"pid": 1, "start": future, "cmd": "x"}])
    assert dsh_install.live_check("web", dst) == []


def test_live_check_skips_without_running_process(tmp_path, monkeypatch):
    """没在跑就跳过——这条检查不该在"只装不跑"的场景下报错。"""
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: [])
    assert dsh_install.live_check("web", tmp_path) == []


def test_parse_start_handles_net_and_garbage():
    assert dsh_install._parse_start("not-a-date") == 0.0
    assert dsh_install._parse_start("") == 0.0
    # .NET 的 'o'：7 位小数 + 偏移，必须能解析（截到秒的退化路径）
    assert dsh_install._parse_start("2026-09-22T10:20:44.1234567+08:00") > 0
    assert dsh_install._parse_start("2026-09-22T10:20:44") > 0


# ----------------------------------------------------------------------
# --restart：已有实例在跑时，双击启动器必须真的重启（而不是起一个注定失败的第二实例）
# ----------------------------------------------------------------------
def _stub_running(monkeypatch, procs):
    monkeypatch.setattr(dsh_install, "running_dsh", lambda profile: procs)


def test_restart_aborts_when_ask_declined(tmp_path, monkeypatch, capsys):
    """`--ask` 且拿不到确认时不能关进程；但必须明说"什么都没做"。"""
    import io

    home = tmp_path / "dsh"
    dsh_install.install(home)
    _stub_running(monkeypatch, [{"pid": 25904, "start": "", "cmd": ""}])
    killed: list = []
    monkeypatch.setattr(dsh_install, "terminate_dsh",
                        lambda procs: killed.append(procs) or [])
    monkeypatch.setattr(dsh_install.sys, "stdin", io.StringIO(""))  # isatty() = False

    rc = dsh_install.main(["--home", str(home), "--restart", "--ask",
                           "--no-roster", "--no-bundle-check", "--no-live"])
    out = capsys.readouterr().out
    assert rc == 1 and killed == []
    assert "EADDRINUSE" in out and "已取消" in out


def test_confirm_never_raises_on_broken_stdin(monkeypatch):
    """stdin 读不到时必须返回 False，而不是把启动流程崩掉。

    实测教训：双击启动器那次就是 `input()` 抛 EOFError、整个流程崩栈——
    重启没发生，人还以为发生了。
    """
    import io

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
    home = tmp_path / "dsh"
    dsh_install.install(home)
    _stub_running(monkeypatch, [{"pid": 1, "start": "", "cmd": ""}])
    killed: list = []
    monkeypatch.setattr(dsh_install, "terminate_dsh",
                        lambda procs: killed.append(procs) or ["已结束 DSH 进程 pid=1"])
    monkeypatch.setattr(dsh_install, "wait_gone",
                        lambda procs, profile="web", timeout=15.0: True)

    # 默认**不问**：双击启动器就是"启动"的明确意图，问一句只会多一个失败点
    rc = dsh_install.main(["--home", str(home), "--restart",
                           "--no-roster", "--no-bundle-check", "--no-live"])
    out = capsys.readouterr().out
    assert rc == 0 and len(killed) == 1
    assert "端口已释放" in out


def test_restart_is_noop_without_running_instance(tmp_path, monkeypatch):
    home = tmp_path / "dsh"
    dsh_install.install(home)
    _stub_running(monkeypatch, [])
    killed: list = []
    monkeypatch.setattr(dsh_install, "terminate_dsh",
                        lambda procs: killed.append(procs) or [])

    rc = dsh_install.main(["--home", str(home), "--restart", "--no-roster",
                           "--no-bundle-check", "--no-live"])
    assert rc == 0 and killed == []


def test_restart_stops_if_process_survives(tmp_path, monkeypatch, capsys):
    """杀了但没退出：必须停住报错，绝不能接着起第二个实例（又会撞端口）。"""
    home = tmp_path / "dsh"
    dsh_install.install(home)
    _stub_running(monkeypatch, [{"pid": 1, "start": "", "cmd": ""}])
    monkeypatch.setattr(dsh_install, "terminate_dsh", lambda procs: ["killed"])
    monkeypatch.setattr(dsh_install, "wait_gone",
                        lambda procs, profile="web", timeout=15.0: False)

    rc = dsh_install.main(["--home", str(home), "--restart",
                           "--no-roster", "--no-bundle-check", "--no-live"])
    out = capsys.readouterr().out
    assert rc == 1 and "未在 15 秒内退出" in out


# ----------------------------------------------------------------------
# 审计桥接线
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
