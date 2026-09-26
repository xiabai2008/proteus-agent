# -*- coding: utf-8 -*-
"""把三个 Proteus agent preset 渲染成一个 DSH bundle（新机制的唯一承载体）。

为什么需要它（2026-09-26 真机实测结论，见 docs/DSH主体化交付说明.md）：
  安装版 DSH 0.1.7-rc.2 起，`$DSH_HOME/.agent-presets/<id>/` 目录发现机制已被移除
  （安装版随附文档原文 "Nothing reads that directory any more"）。preset 改为
  `@deepseek-ai/dsh-agent-preset` 声明行，由 bundle 补丁承载，用
  `plugin_manager` `install_bundle` 装进 profile。

  实测出来的三条解析规则（探针对照，2026-09-26）：
    1. bundle 补丁里插入声明行 -> 生效；裸包名（@deepseek-ai/dsh-*）可解析；
    2. `./x.mjs` 相对行的解析基准是 **profile 目录**，不是 bundle 目录
       （文件只在 bundle 里 = broken: never started；只在 profile 里 = OK）；
    3. **包自引用子路径**（包名 + exports 子路径）可解析 —— 本脚本采用这条，
       四个共享插件因此留在仓库 bundle 内，profile 目录不再需要副本。

单一实现来源仍是 `dsh/.agent-presets/_shared/`：
  - `agent.cordis.template.yml` 渲染成三个预设的插件清单；
  - `proteus-*.mjs` 四个文件**复制**进 bundle（Node 的 exports 不允许指向包外），
    复制后由 `tools/dsh_install.py --check` 做哈希校验防漂移。

产物（全部落在 dsh/proteus-presets/）：
  package.json / cordis.patch.yml / proteus-{persona,tools-policy,supervisor,commands}.mjs

用法：
  python tools/render_preset_bundle.py            # 渲染（幂等）
  python tools/render_preset_bundle.py --check    # 只校验产物与来源是否一致
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO / "dsh" / ".agent-presets"
SHARED = SRC_ROOT / "_shared"
TEMPLATE = SHARED / "agent.cordis.template.yml"
OUT = REPO / "dsh" / "proteus-presets"

BUNDLE_NAME = "dsh-proteus-presets"
BUNDLE_VERSION = "0.1.0"

# 四个共享插件的本地文件 -> bundle 包内的 exports 子路径。
# preset 行写包名子路径（实测可解析），不写 './x.mjs'（实测只在 profile 目录下有效）。
SHARED_FILES = {
    "proteus-persona.mjs": "persona",
    "proteus-tools-policy.mjs": "tools-policy",
    "proteus-supervisor.mjs": "supervisor",
    "proteus-commands.mjs": "commands",
}
LOCAL_ROW_REWRITES = {
    "name: './proteus-persona.mjs'": f"name: '{BUNDLE_NAME}/persona'",
    "name: './proteus-tools-policy.mjs'": f"name: '{BUNDLE_NAME}/tools-policy'",
    "name: './proteus-supervisor.mjs'": f"name: '{BUNDLE_NAME}/supervisor'",
    "name: './proteus-commands.mjs'": f"name: '{BUNDLE_NAME}/commands'",
}

# 三个 preset：与 tools/dsh_install.py 的 PRESETS 同源（默认模式/人格/会话键/标签），
# 显示名与描述取自各 preset.yml（roster 里给人看的）。
PRESETS = [
    {
        "id": "proteus-pentest",
        "mode": "pentest-standard",
        "persona": "dsh-persona.md",
        "session_key": "pentest",
        "label": "渗透场景",
    },
    {
        "id": "proteus-ctf-web",
        "mode": "ctf-web",
        "persona": "dsh-persona-ctf.md",
        "session_key": "ctf-web",
        "label": "CTF Web 场景",
    },
    {
        "id": "proteus-ctf-crypto",
        "mode": "ctf-crypto",
        "persona": "dsh-persona-ctf.md",
        "session_key": "ctf-crypto",
        "label": "CTF Crypto 场景",
    },
]


def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def preset_meta(preset_id: str) -> dict[str, str]:
    """读 dsh/.agent-presets/<id>/preset.yml 的 name/description/order。"""
    meta: dict[str, str] = {}
    for line in read_text(SRC_ROOT / preset_id / "preset.yml").splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            meta[key.strip()] = value.strip()
    return meta


def render_plugins(cfg: dict[str, str]) -> str:
    """渲染某个 preset 的插件清单（缩进 10 空格，落在声明行 config.plugins 之下）。"""
    text = read_text(TEMPLATE)
    for token, value in (
        ("{{PRESET_ID}}", cfg["id"]),
        ("{{PRESET_LABEL}}", cfg["label"]),
        ("{{DEFAULT_MODE}}", cfg["mode"]),
        ("{{PERSONA_PROMPT}}", cfg["persona"]),
        ("{{SESSION_KEY}}", cfg["session_key"]),
    ):
        text = text.replace(token, value)
    # 只查本部署的占位符：模板注释里还有 DSH 自己的 `{{model}}` / `{{cwd}}` 字样
    leftover = [t for t in ("{{PRESET_ID}}", "{{PRESET_LABEL}}", "{{DEFAULT_MODE}}",
                            "{{PERSONA_PROMPT}}", "{{SESSION_KEY}}") if t in text]
    if leftover:
        raise SystemExit(f"模板仍有未替换占位符 {leftover}：{cfg['id']}")
    for old, new in LOCAL_ROW_REWRITES.items():
        text = text.replace(old, new)

    body = [ln for ln in text.splitlines() if ln.startswith("- id:") or ln.startswith(" ")]
    indented = [("          " + ln).rstrip() if ln.strip() else "" for ln in body]
    return "\n".join(indented)


def render_patch() -> str:
    header = f"""# dsh-proteus-presets —— Proteus 三个 agent preset 的声明行（自动生成）
#
# 生成器：tools/render_preset_bundle.py（**不要手改本文件**，改模板或脚本后重跑）。
# 装载方式：plugin_manager -> action: install_bundle -> target 填本目录绝对路径。
#
# 为什么有本文件（2026-09-26 真机实测）：
#   * 新版 DSH 已移除 `$DSH_HOME/.agent-presets/` 目录发现（安装版随附文档：
#     "Nothing reads that directory any more"）；preset 只能由 bundle 补丁声明。
#   * `./x.mjs` 相对行的解析基准是 profile 目录而非 bundle 目录（探针实测：
#     文件只在 bundle 里 -> broken "never started"；只在 profile 目录里 -> OK）。
#     所以插件行写**包自引用子路径**，四个共享插件留在本 bundle 内。
#
# 声明行字段：id(必填) / plugins(必填) / name / description / order（roster 排序）。
# Loader 行 id 约定 `preset-<config.id>`。
"""
    blocks = [header, "- insert:"]
    for cfg in PRESETS:
        meta = preset_meta(cfg["id"])
        blocks.append(f"""    - id: preset-{cfg['id']}
      name: '@deepseek-ai/dsh-agent-preset'
      config:
        id: {cfg['id']}
        name: {meta['name']}
        description: {meta['description']}
        order: {meta['order']}
        plugins:
{render_plugins(cfg)}""")
    blocks.append(f"""    # ── host 平面审计行（与上面三个 preset 同 bundle，role 分工见插件文件头）──
    # session/event 是全局事件，host 平面可见；裁决行必须在 preset 作用域内，
    # 故同一份实现在两个挂载点按 role 分工（audit / policy）。
    - id: proteus-bridge
      name: '{BUNDLE_NAME}/tools-policy'
      config:
        spoolPath: !!js (process.env.PENTEST_WS || '.') + '/proteus-agent/data/dsh-events.jsonl'
        role: audit""")
    return "\n".join(blocks) + "\n"


def render_package_json() -> str:
    exports = {f"./{key}": f"./{name}" for name, key in SHARED_FILES.items()}
    exports["./cordis.patch.yml"] = "./cordis.patch.yml"
    exports["./package.json"] = "./package.json"
    payload = {
        "name": BUNDLE_NAME,
        "version": BUNDLE_VERSION,
        "private": True,
        "type": "module",
        "description": "Proteus agent presets (pentest / ctf-web / ctf-crypto) + host-plane audit row.",
        "exports": exports,
        "dsh": {"bundle": {"patch": "./cordis.patch.yml"}},
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def expected_files() -> dict[str, str]:
    """需要**渲染**的文本产物（补丁 + package.json）。

    四个共享插件不在其中：它们是副本，走 `copy_files()` 逐字节复制——
    解码再编码会把源文件自己的行尾（`tools-policy` / `commands` 是 CRLF）
    改成 LF，导致"副本 vs 来源"字节比对失败（实测踩过）。
    """
    return {"cordis.patch.yml": render_patch(),
            "package.json": render_package_json()}


def copy_files() -> tuple[str, ...]:
    """需要逐字节复制的共享实现（bundle 内的插件本体）。"""
    return tuple(SHARED_FILES)


def check(files: dict[str, str]) -> int:
    problems = []
    for name, want in files.items():
        path = OUT / name
        if not path.exists():
            problems.append(f"缺少 {path.relative_to(REPO)}")
            continue
        if read_text(path) != want:
            problems.append(f"与来源不一致（需重跑渲染器）：{path.relative_to(REPO)}")
    for name in copy_files():
        path = OUT / name
        if not path.exists():
            problems.append(f"缺少 {path.relative_to(REPO)}")
            continue
        if path.read_bytes() != (SHARED / name).read_bytes():
            problems.append(f"副本与 _shared/ 漂移：{path.relative_to(REPO)}")
    if problems:
        print("bundle 校验失败：")
        for p in problems:
            print("  ✗", p)
        return 1
    total = len(files) + len(copy_files())
    print(f"bundle 校验通过：{total} 个文件与 _shared/ 来源一致（{OUT.relative_to(REPO)}）")
    return 0


def write_bundle() -> list[str]:
    """把产物写进 bundle 目录（幂等）；返回写出的文件名列表。

    渲染后立刻自检：三个声明都在、且**没有** './proteus-*.mjs' 相对行
    （新机制下按 profile 目录解析，写相对行必然 broken）。
    """
    files = expected_files()
    OUT.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, text in files.items():
        # newline="" —— 不做行尾翻译：本仓库用 LF，Windows 上 write_text 默认会把
        # \n 变成 \r\n，与来源不一致（实测）。
        with open(OUT / name, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        written.append(name)
    for name in copy_files():
        (OUT / name).write_bytes((SHARED / name).read_bytes())
        written.append(name)

    patch = files["cordis.patch.yml"]
    for cfg in PRESETS:
        if f"id: {cfg['id']}\n" not in patch:
            raise SystemExit(f"渲染结果缺少声明 {cfg['id']}")
    if "name: './proteus-" in patch:
        raise SystemExit("渲染结果仍有 './proteus-*.mjs' 相对行（新机制下解析不到）")
    return written


def main() -> int:
    files = expected_files()
    if "--check" in sys.argv:
        return check(files)
    for name in write_bundle():
        print("写入", (OUT / name).relative_to(REPO))
    print(f"渲染完成：{len(PRESETS)} 个 preset 声明 + 1 个审计行 -> {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
