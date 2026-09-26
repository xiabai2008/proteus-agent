# -*- coding: utf-8 -*-
"""bundle 承载体的一致性测试（2026-09-26 preset 载体迁移）。

背景：安装版 DSH 已移除 `$DSH_HOME/.agent-presets/` 目录发现，preset 改由
bundle 补丁里的声明行承载（见 tools/render_preset_bundle.py 文件头与
docs/DSH主体化交付说明.md）。本用例把"渲染产物 vs 来源"钉在 pytest 里——
判据落在**消费方读到的东西**上（install_bundle 实际装的那份文件），
而不是渲染器自己的中间态。

覆盖：
  1. 仓库里的 bundle 与 `_shared/` 来源一致（渲染器 --check 的语义）；
  2. 四个共享插件是字节级副本，不漂移；
  3. 三个声明行齐全、Loader 行 id 命名正确、无残留占位符；
  4. 插件行写**包自引用子路径**——实测 `./x.mjs` 相对行按 profile 目录解析，
     bundle 目录里的相对行会得到 broken "never started"（探针实测，2026-09-26）；
  5. package.json 的 exports 覆盖四个插件与补丁文件（包自引用可解析的前提）。
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "render_preset_bundle", ROOT / "tools" / "render_preset_bundle.py")
render_preset_bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render_preset_bundle)

BUNDLE = ROOT / "dsh" / "proteus-presets"
PATCH = BUNDLE / "cordis.patch.yml"
PKG = BUNDLE / "package.json"

PRESET_IDS = ("proteus-pentest", "proteus-ctf-web", "proteus-ctf-crypto")


def test_bundle_matches_shared_sources():
    """仓库里的 bundle 必须与 `_shared/` 渲染结果逐字节一致。"""
    expected = render_preset_bundle.expected_files()
    for name, want in expected.items():
        path = BUNDLE / name
        assert path.is_file(), f"bundle 缺文件：{name}（跑 python tools/render_preset_bundle.py）"
        assert path.read_text(encoding="utf-8") == want, (
            f"{name} 与 _shared/ 来源不一致：改模板/插件后要重跑 tools/render_preset_bundle.py")


def test_shared_plugins_are_byte_identical_copies():
    """四个共享插件是逐字节副本（Node exports 不允许指向包外），必须防漂移。"""
    shared = ROOT / "dsh" / ".agent-presets" / "_shared"
    for name in render_preset_bundle.copy_files():
        assert (BUNDLE / name).read_bytes() == (shared / name).read_bytes(), \
            f"{name} 与 _shared/ 下的实现漂移了"


def test_declares_three_presets_with_conventional_row_ids():
    text = PATCH.read_text(encoding="utf-8")
    for preset_id in PRESET_IDS:
        assert f"    - id: preset-{preset_id}\n" in text, f"缺声明行 preset-{preset_id}"
        assert f"        id: {preset_id}\n" in text, f"声明里缺 config.id: {preset_id}"
    assert "name: '@deepseek-ai/dsh-agent-preset'" in text
    # host 平面审计行与三个 preset 同 bundle（同一份实现、role 分工）
    assert "    - id: proteus-bridge\n" in text


def test_no_leftover_placeholders_or_legacy_relative_rows():
    """渲染漏占位符 = 行 config 变字面量；相对行 = 必然 broken。"""
    text = PATCH.read_text(encoding="utf-8")
    for token in ("{{PRESET_ID}}", "{{PRESET_LABEL}}", "{{DEFAULT_MODE}}",
                  "{{PERSONA_PROMPT}}", "{{SESSION_KEY}}"):
        assert token not in text, f"未替换的占位符：{token}"
    assert not re.search(r"name: '\./", text), \
        "插件行不能写 './x.mjs'——实测相对基准是 profile 目录，bundle 内的会 broken"


def test_plugin_rows_use_package_self_reference():
    """四个本地插件行必须写 <包名>/<子路径>（裸包名或包自引用均可解析）。"""
    text = PATCH.read_text(encoding="utf-8")
    for key in render_preset_bundle.SHARED_FILES.values():
        assert f"name: '{render_preset_bundle.BUNDLE_NAME}/{key}'" in text, \
            f"插件行未使用包自引用子路径：{key}"


def test_package_exports_cover_plugins_and_patch():
    pkg = json.loads(PKG.read_text(encoding="utf-8"))
    exports = pkg["exports"]
    for name, key in render_preset_bundle.SHARED_FILES.items():
        assert exports[f"./{key}"] == f"./{name}"
    assert exports["./cordis.patch.yml"] == "./cordis.patch.yml"
    assert pkg["dsh"]["bundle"]["patch"] == "./cordis.patch.yml"


def test_preset_metadata_matches_source_preset_yml():
    """roster 显示名/描述/排序取自各 preset.yml，渲染后不得走样。"""
    text = PATCH.read_text(encoding="utf-8")
    for preset_id in PRESET_IDS:
        meta = render_preset_bundle.preset_meta(preset_id)
        assert f"        name: {meta['name']}\n" in text
        assert f"        description: {meta['description']}\n" in text
        assert f"        order: {meta['order']}\n" in text
