"""内核文件工具（file_read / file_write / file_edit）。

为什么需要（路线图 P1-1，2026-09-27 实测）：CLI 路径此前**没有任何通用文件读写**
——CTF 工具面里只有 `file_type`（前 200 字符预览）与容器内 `python_solve`
（每次重发整段脚本）。真机对照很直白：同一道「云栈密令」，宿主路径用 `edit`
迭代出 18KB 的 ARM64 解释器（113 次调用），而 CLI 路径做同样的事只能一遍遍
重发脚本。文件工具把"写脚本 → 跑 → 改 → 再跑"这条最基本的循环补上。

三条边界（硬规则 1 / 3 的延伸）：

- **作用域限 data 目录**（容器视角即 `/samples`，两边同一份）：内核 CLI 模式
  没有 shell，工具是唯一的落地通道，可达范围必须钉死。入参两种视角都收
  （`/samples/...` 与宿主相对/绝对路径），解析后**必须落在 data 目录内**。
- **状态与审计文件只读**（`_PROTECTED`）：`session-scope*` / `session-mode*`
  （人工授权与模式）、`chain.jsonl`（证据链）、`missions/`（作战记录）、
  `skills/`（知识库）——写它们等于自我授权 / 篡改证据 / 绕过 `reflect` 的
  "无证据不进库"纪律，一律拒绝；读不受限。
- **写操作走 permission 档位**（各 CTF 模式 `require_confirm`；未授权会话
  一律被拒），但**不标 `dangerous`**：沙箱判据里 "dangerous ⇒ 必须进容器"，
  而 function 工具进不了容器——标了会在真机上以"需要隔离但类型为 function"
  被拒（2026-09-27 实测撞到）。作用域由上面的路径守卫兜住，与 `report_gen`
  同规格（宿主侧写、范围自限）。返回里带 sha256 与字节数，便于入链核对。
"""
from __future__ import annotations

import hashlib
from pathlib import Path

#: 只读保护：授权/模式状态、证据链、作战记录、知识库（相对 data 根）
_PROTECTED_NAMES = ("session-scope", "session-mode")
_PROTECTED_FILES = ("chain.jsonl",)
_PROTECTED_DIRS = ("missions", "skills")

#: 读取上限（字符）：默认与 http_raw 同口径；硬上限防止把上下文撑爆
READ_DEFAULT_CHARS = 4000
READ_MAX_CHARS = 20000


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _data_root() -> Path:
    from penagent.sandbox import data_root

    return Path(data_root()).resolve()


def _workspace_path(raw: str) -> tuple[Path, str]:
    """解析入参路径并做**作用域校验**：返回 (宿主路径, 错误说明)。

    路径口径（与本工具的存在理由一致：内核的文件宇宙就是 data 目录）：

    - `/samples/x` → `<data>/x`（容器视角，与 python_solve 里看到的同一份）；
    - `data/x` / `./data/x` → `<data>/x`（模型习惯把 data 前缀写出来）；
    - 其它相对路径 → `<data>/<path>`——**刻意不用进程 cwd**：cwd 相对会悄悄
      够到仓库（含不入库的 `.env`）或用户目录，与"作用域限 data"直接矛盾；
    - 绝对路径：必须落在 data 目录内，否则拒绝。

    错误说明非空时路径不可用——原样回给模型（带上允许的根与解析结果）。
    """
    root = _data_root()
    text = str(raw or "").strip().replace("\\", "/")
    if not text:
        return root, "缺少 path 参数（题面文件与脚本都在 data 目录内）"
    if text == "/samples" or text.startswith("/samples/"):
        text = text[len("/samples"):].lstrip("/")
    if text.startswith("./"):
        text = text[2:]
    if text.startswith("data/"):
        text = text[len("data/"):]
    candidate = Path(text)
    resolved = candidate if candidate.is_absolute() else (root / text)
    try:
        resolved = resolved.resolve()
    except OSError as exc:                       # pragma: no cover - 极端路径
        return root, f"路径无法解析: {exc}"
    if resolved != root and not resolved.is_relative_to(root):
        return root, (f"路径越界：{resolved} 不在允许的 data 目录 {root} 内。"
                      f"内核文件工具只对 data 目录读写（容器视角 /samples）；"
                      f"题面文件先由人放进 data（或宿主侧复制进来）")
    return resolved, ""


def _relative(path: Path) -> str:
    try:
        return path.relative_to(_data_root()).as_posix()
    except ValueError:                            # pragma: no cover - 已在上游拦住
        return path.as_posix()


def _protected_reason(path: Path) -> str:
    """状态/审计文件的写保护理由（'' = 可写）。"""
    rel = _relative(path)
    name = path.name
    if name.startswith(_PROTECTED_NAMES):
        return (f"{rel} 是会话状态文件（授权 / 模式）：只能由人通过 "
                f"`/proteus-scope`、`/proteus-mode` 或内核 CLI 修改"
                f"——模型不能自我授权、也不能自己切模式。"
                f"可用做法：把请求写进结论让人执行，或改写到 data 内的其他路径")
    if name in _PROTECTED_FILES:
        return f"{rel} 是证据链：只由工具执行层追加，不允许工具改写"
    parts = Path(rel).parts
    if parts and parts[0] in _PROTECTED_DIRS:
        return (f"{rel} 属于 {parts[0]}/（作战记录与知识库）：写入要经内核流程"
                f"（report_gen / reflect），直接改写会绕过留证与"
                f"\"无证据不进库\"纪律")
    return ""


def file_read(path: str = "", max_chars: int = READ_DEFAULT_CHARS,
              grep: str = "") -> dict:
    """读 data 目录内的文件（文本按 UTF-8 解码，二进制给十六进制预览）。

    - `max_chars`：正文上限（默认 4000，硬上限 20000）——内核回灌给模型时
      还会再截断（约 2500 字符），要长脚本里的关键片段请用 `grep`；
    - `grep`：正则提取（在**完整文件**上做，绕过截断），返回逐匹配 + 命中行；
    - 二进制（含 NUL 字节）：不给乱码，回十六进制预览 + 大小。
    """
    target, problem = _workspace_path(path)
    if problem:
        return {"error": problem}
    if not target.is_file():
        from penagent.ctf_tools import _candidates

        return {"error": f"文件不存在: {_relative(target)}",
                "candidates": _candidates(target),
                "hint": "同目录候选见 candidates；先 file_type 确认类型"}
    try:
        raw = target.read_bytes()
    except OSError as exc:
        return {"error": f"读取失败: {exc}"}
    try:
        cap = max(256, min(int(max_chars or READ_DEFAULT_CHARS), READ_MAX_CHARS))
    except (TypeError, ValueError):
        cap = READ_DEFAULT_CHARS
    result: dict = {"path": _relative(target), "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest()[:16]}
    if b"\x00" in raw[:4096]:
        result.update(binary=True,
                      preview_hex=raw[:256].hex(" "),
                      note="二进制文件：只给预览。要解析它用 python_solve")
        return result
    text = raw.decode("utf-8", errors="replace")
    result["text"] = text[:cap]
    result["truncated"] = len(text) > cap
    result["lines"] = text.count("\n") + (0 if text.endswith("\n") else 1)
    if result["truncated"]:
        result["note"] = ("正文已截断——要特定片段用 grep 参数给正则"
                          "（在完整内容上提取）")
    if grep:
        from penagent.builtin_tools import _grep_body

        result["grep"] = _grep_body(text, grep)
        result["grep"]["scanned_chars"] = len(text)
    return result


def file_write(path: str = "", content: str = "", append: bool = False) -> dict:
    """在 data 目录内写文本文件（父目录自动创建；默认覆盖）。

    返回 `bytes` / `sha256` / `path`：写操作留痕可核对（证据链里记的是调用
    参数与返回值，sha256 让"这次写入的内容"事后可验证）。
    """
    target, problem = _workspace_path(path)
    if problem:
        return {"error": problem}
    protected = _protected_reason(target)
    if protected:
        return {"error": f"拒绝写入：{protected}"}
    if target.is_dir():
        return {"error": f"{_relative(target)} 是目录"}
    data = content if isinstance(content, str) else str(content)
    # 模型常把布尔写成字符串（"true"/"false"），按真值语义收
    mode_append = str(append).strip().lower() in ("1", "true", "yes", "on")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a" if mode_append else "w", encoding="utf-8",
                         newline="") as fh:
            fh.write(data)
    except OSError as exc:
        return {"error": f"写入失败: {exc}"}
    return {"path": _relative(target), "bytes": len(data.encode("utf-8")),
            "sha256": _sha256_text(data)[:16], "append": mode_append}


def file_edit(path: str = "", old: str = "", new: str = "", count: int = 0) -> dict:
    """在 data 目录内做精确串替换（`old` → `new`）。

    安全语义（与主流编辑工具同口径）：默认**要求唯一匹配**——出现 0 次报
    "未找到"、出现多次报"不唯一"并给出出现次数，避免改错位置；要连续替换
    多处时显式给 `count`（替换到多 `count` 处或全部替换完为止）。
    """
    target, problem = _workspace_path(path)
    if problem:
        return {"error": problem}
    protected = _protected_reason(target)
    if protected:
        return {"error": f"拒绝写入：{protected}"}
    if not target.is_file():
        from penagent.ctf_tools import _candidates

        return {"error": f"文件不存在: {_relative(target)}",
                "candidates": _candidates(target),
                "hint": "同目录候选见 candidates；也可用 file_write 新建该文件"}
    if old == "":
        return {"error": "old 不能为空（要整篇替换请用 file_write）"}
    try:
        want = int(str(count or 0).strip() or 0)
    except ValueError:
        return {"error": f"count 不是整数: {count!r}（不给=要求唯一匹配）"}
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {"error": f"读取失败（非 UTF-8 文本？）: {exc}"}
    found = text.count(old)
    if found == 0:
        return {"error": "old 未出现：内容没有变化",
                "hint": "先 file_read（可带 grep）确认原文片段，注意空白与换行"}
    if found > 1 and want <= 0:
        return {"error": f"old 不唯一（出现 {found} 次）：未做修改",
                "hint": f"把 old 写得更具体，或用 count={found} 显式替换多处"}
    times = found if want <= 0 else min(want, found)
    updated = text.replace(old, new, times if want > 0 else -1)
    try:
        target.write_text(updated, encoding="utf-8", newline="")
    except OSError as exc:
        return {"error": f"写入失败: {exc}"}
    return {"path": _relative(target), "replaced": times,
            "bytes": len(updated.encode("utf-8")),
            "sha256": _sha256_text(updated)[:16]}
