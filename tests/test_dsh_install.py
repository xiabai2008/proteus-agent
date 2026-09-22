"""DSH 接入安装器测试：机制性校验的每一条都要能独立触发。

为什么值得测：这三条校验挡的都是**静默失效**——preset 少一个文件就整份从
选择器里消失、`!!js` 写错就求值成 `[object Object]`、审计桥没接线就"旁路
不留痕"。它们坏掉时不会有人报错，只会有人以为一切正常。
"""
import importlib.util
import json
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
    """造一个最小 preset 目录：agent.cordis.yml + preset.yml。"""
    dst = tmp_path / "proteus"
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "agent.cordis.yml").write_text(body, encoding="utf-8")
    (dst / "preset.yml").write_text("name: t\n", encoding="utf-8")
    return dst


def test_verify_accepts_installed_package_rows(tmp_path):
    """包名行（@deepseek-ai/…）不做本地存在性检查——那是 roster 的活。"""
    dst = _preset_dir(tmp_path, "- id: a\n  name: '@deepseek-ai/dsh-persona'\n")
    assert dsh_install.verify_preset(dst) == []


def test_verify_flags_missing_relative_plugin(tmp_path):
    """相对 specifier 解析不到 = 整份 preset broken（这是最贵的一种静默失效）。"""
    dst = _preset_dir(
        tmp_path,
        "- id: policy\n  name: './proteus-tools-policy.mjs'\n  config:\n    role: policy\n")
    problems = dsh_install.verify_preset(dst)
    assert any("相对 specifier" in p and "proteus-tools-policy.mjs" in p
               for p in problems), problems

    # 文件补齐后必须转干净——否则校验会变成"永远报错"的噪音
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


def test_check_bundle_reports_missing_wiring(tmp_path):
    home = tmp_path / "dsh"
    web = home / "profiles" / "web"
    web.mkdir(parents=True)
    (web / "package.json").write_text(json.dumps({"dependencies": {}}),
                                      encoding="utf-8")
    problems = dsh_install.check_bundle(home, "web")
    assert any("依赖里没有" in p for p in problems)
    assert any("bundles 里没有" in p for p in problems)

    (web / "package.json").write_text(json.dumps({
        "dependencies": {dsh_install.BRIDGE_NAME: "link:..."},
        "dsh": {"profile": {"bundles": [dsh_install.BRIDGE_NAME]}},
    }), encoding="utf-8")
    assert dsh_install.check_bundle(home, "web") == []


def test_check_bundle_reports_missing_profile(tmp_path):
    assert dsh_install.check_bundle(tmp_path / "dsh", "web")


def test_install_links_then_check_is_clean(tmp_path):
    """装完即可通过 `--check`；再装一次是幂等（不重复备份、不重指向）。"""
    home = tmp_path / "dsh"
    try:
        notes = dsh_install.install(home, copy=False)
    except RuntimeError as exc:                  # 既建不了 symlink 也建不了 junction
        pytest.skip(f"本机建不了目录链接：{exc}")
    assert any("已建" in n for n in notes), notes

    dst = home / ".agent-presets" / "proteus"
    assert (dst / "agent.cordis.yml").is_file()   # 经链接能读到真源
    assert dsh_install.verify_preset(dst) == []

    again = dsh_install.install(home, copy=False)
    assert any("无需改动" in n for n in again), again
    assert list(dst.parent.glob("proteus.bak-*")) == []


def test_install_backs_up_existing_real_directory(tmp_path):
    """已存在的真实目录（旧的手工复制版）先备份再链接，不静默覆盖。"""
    home = tmp_path / "dsh"
    dst = home / ".agent-presets" / "proteus"
    dst.mkdir(parents=True)
    (dst / "agent.cordis.yml").write_text("# 旧副本\n", encoding="utf-8")

    try:
        notes = dsh_install.install(home, copy=False)
    except RuntimeError as exc:
        pytest.skip(f"本机建不了目录链接：{exc}")
    assert any("已备份" in n for n in notes), notes
    backups = list(dst.parent.glob("proteus.bak-*"))
    assert len(backups) == 1
    assert (backups[0] / "agent.cordis.yml").read_text(encoding="utf-8") == "# 旧副本\n"


def test_check_notes_copy_install_as_drift_risk(tmp_path, capsys):
    """`--check` 必须能看出"复制安装"——这正是漂移的根因。

    复制不是错误（可能是有意为之），所以不失败；但**必须看得见**，否则
    "仓库改了、装的那份还是旧的"会一直是静默的。
    """
    home = tmp_path / "dsh"
    dsh_install.install(home, copy=True)
    rc = dsh_install.main(["--home", str(home), "--check", "--no-roster",
                           "--no-bundle-check"])
    out = capsys.readouterr().out
    assert "复制安装" in out
    assert rc == 0


def test_check_does_not_warn_for_link_install(tmp_path, capsys):
    home = tmp_path / "dsh"
    try:
        dsh_install.install(home, copy=False)
    except RuntimeError as exc:
        pytest.skip(f"本机建不了目录链接：{exc}")
    rc = dsh_install.main(["--home", str(home), "--check", "--no-roster",
                           "--no-bundle-check"])
    out = capsys.readouterr().out
    assert "复制安装" not in out
    assert rc == 0


def test_install_copy_mode_materializes_files(tmp_path):
    home = tmp_path / "dsh"
    notes = dsh_install.install(home, copy=True)
    dst = home / ".agent-presets" / "proteus"
    assert any("已复制" in n for n in notes), notes
    assert dsh_install.verify_preset(dst) == []
    assert not (dsh_install.os.path.islink(dst) or dsh_install._is_reparse_point(dst))
