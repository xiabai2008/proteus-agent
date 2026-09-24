"""CTF 解题工具（Crypto / Misc）：解码链与文件识别（纯 stdlib 实现）。

为什么这几个是 function 工具而不是 CLI：本机 bin 目录里没有 base64 / xxd /
file 这类独立二进制（实测 `<TOOLS_DIR>\\bin` 只有 rsactftool /
stegoveritas / jadx / x64dbg 等），用 stdlib 实现既能离线确定性运行，也免去
Windows 下的外部依赖。需要外部二进制的（RsaCtfTool、python 一次性脚本沙箱）
仍以 CLI 形式登记，见 `ctf_tools.json`。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import urllib.parse
from pathlib import Path

_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"), (b"GIF89a", "gif"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip/docx/xlsx/jar/apk"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!", "rar"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe/exe/dll"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"RIFF", "riff/wav/avi"),
)

_CODECS = ("base64", "base64url", "hex", "url", "rot13", "binary", "reverse")


def _to_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.hex()


#: 容器视角路径前缀（宿主 `data/` 目录在容器内的只读挂载点，见 sandbox.py）
SAMPLES_PREFIX = "/samples"
#: 失败时回给模型的同目录候选上限（帮它自我纠正，而不是反复重试同一个错路径）
MAX_CANDIDATES = 8


def _candidates(path: Path) -> list[str]:
    """同目录下的候选文件名（目录不存在/不可读时返回空列表）。"""
    try:
        return sorted(x.name for x in path.parent.iterdir()
                      if x.is_file())[:MAX_CANDIDATES]
    except OSError:
        return []


def _resolve_path(raw: str) -> tuple[Path, list[str]]:
    """把入参路径解析成宿主路径：返回 `(优先路径, 已尝试路径列表)`。

    两种视角在**同一套工具面**里必须等价（R-38，2026-09-24 实测）：

    - **容器视角** `/samples/...` → 宿主 data 目录（`sandbox.data_root()`）。
      容器化 MCP 工具（binwalk / yara / capa）与 `checksec_bin` 都用这个约定，
      模型自然会把同一约定套到宿主侧工具上；
    - **宿主视角**：绝对路径原样；相对路径按进程 cwd 解析，未命中再试 data
      目录之下（模型常把 `data/eval-ctf/x` 简写成 `eval-ctf/x`）。

    不统一的代价是实打实的：一次 CTF 会话里模型照 `/samples/...` 调宿主侧的
    `file_type`，连失败 57 次、60 步预算耗尽（`docs/修复待办清单.md` R-38）。
    """
    from penagent.sandbox import data_root

    text = str(raw or "").strip()
    norm = text.replace("\\", "/")
    if norm == SAMPLES_PREFIX or norm.startswith(SAMPLES_PREFIX + "/"):
        rel = norm[len(SAMPLES_PREFIX):].strip("/")
        mapped = Path(data_root()) / rel if rel else Path(data_root())
        return mapped, [str(mapped)]

    path = Path(text)
    if path.is_absolute():
        return path, [str(path)]

    attempts = [str(path)]
    if not path.is_file():
        under_data = Path(data_root()) / text
        attempts.append(str(under_data))
        if under_data.is_file():
            return under_data, attempts
    return path, attempts


def _decode_once(text: str, codec: str) -> bytes:
    name = (codec or "").strip().lower()
    if name == "base64":
        return base64.b64decode(text.strip(), validate=False)
    if name == "base64url":
        padded = text.strip() + "=" * (-len(text.strip()) % 4)
        return base64.urlsafe_b64decode(padded)
    if name == "hex":
        return binascii.unhexlify("".join(text.split()))
    if name == "url":
        return urllib.parse.unquote_to_bytes(text)
    if name == "rot13":
        return codecs.encode(text, "rot_13").encode("utf-8")
    if name == "reverse":
        return text[::-1].encode("utf-8")
    if name == "binary":
        bits = "".join(ch for ch in text if ch in "01")
        return int(bits, 2).to_bytes(len(bits) // 8, "big")
    raise ValueError(f"不支持的解码方式: {codec!r}（可用 {_CODECS}）")


def codec_decode(data: str, codec: str = "base64") -> dict:
    """单步解码：base64 / base64url / hex / url / rot13 / reverse / binary。"""
    try:
        raw = _decode_once(str(data), codec)
    except (binascii.Error, ValueError) as exc:
        return {"codec": codec, "error": str(exc)}
    text = _to_text(raw)
    return {"codec": codec, "result": text, "bytes": len(raw),
            "is_text": raw.decode("utf-8", errors="replace").isprintable()}


def codec_chain(data: str, codecs: str = "") -> dict:
    """按顺序连续解码：codecs 形如 "hex,base64,rot13"（从左到右依次施加）。"""
    steps = [s for s in str(codecs).replace(" ", "").split(",") if s]
    if not steps:
        return {"error": f"未指定解码链（可用 {_CODECS}）"}
    current = str(data)
    trace = []
    for step in steps:
        try:
            raw = _decode_once(current, step)
        except (binascii.Error, ValueError) as exc:
            return {"error": f"第 {len(trace) + 1} 步 {step} 失败: {exc}",
                    "trace": trace}
        current = _to_text(raw)
        trace.append({"codec": step, "result": current[:200]})
    return {"result": current, "steps": steps, "trace": trace}


def file_type(path: str) -> dict:
    """按魔数识别文件类型；文本文件附带前 200 字符预览。

    路径两种视角都支持（见 `_resolve_path`）：容器视角 `/samples/...` 映射到宿主
    data 目录，宿主视角按绝对路径或进程 cwd 解析（未命中再试 data 目录之下）。
    失败时给出**可操作的错误**（已尝试路径 / cwd / `/samples` 映射目标 / 同目录
    候选文件）——只说"文件不存在"等于逼模型反复重试同一个错路径。
    """
    p, attempts = _resolve_path(path)
    if not p.is_file():
        from penagent.sandbox import data_root

        return {
            "path": str(p),
            "error": (f"文件不存在: {p}（已尝试: {'、'.join(attempts)}；"
                      f"cwd={Path.cwd()}；{SAMPLES_PREFIX} 映射到 {data_root()}）"),
            "candidates": _candidates(p),
        }
    head = p.read_bytes()[:64]
    kind = "data"
    for magic, name in _MAGIC:
        if head.startswith(magic):
            kind = name
            break
    info = {"path": str(p), "size": p.stat().st_size, "type": kind}
    if kind == "data":
        try:
            text = p.read_text(encoding="utf-8")
            info["type"] = "text"
            info["preview"] = text[:200]
        except (UnicodeDecodeError, OSError):
            info["preview"] = head.hex()
    return info


def register_ctf_tools(center, modes=("ctf-web", "ctf-crypto")) -> int:
    """把 CTF function 工具登记进注册中心（模式可用性由调用方给定）。"""
    from penagent.registry import SOURCE_FUNCTION
    from penagent.tools import ToolSpec

    specs = [
        ToolSpec(name="codec_decode",
                 description="单步解码（base64/base64url/hex/url/rot13/"
                             "reverse/binary），返回解码后文本",
                 parameters={"data": {"type": "string"},
                             "codec": {"type": "string"}},
                 fn=codec_decode),
        ToolSpec(name="codec_chain",
                 description="按顺序连续解码（如 hex,base64,rot13），"
                             "用于多层编码链",
                 parameters={"data": {"type": "string"},
                             "codecs": {"type": "string"}},
                 fn=codec_chain),
        ToolSpec(name="file_type",
                 description="识别文件类型（魔数），文本文件返回前 200 字符预览。"
                             "路径两种视角都支持：容器视角 /samples/...（映射到 "
                             "data 目录，与 binwalk/yara/capa/checksec_bin 一致）"
                             "与宿主视角（绝对路径或相对进程 cwd）",
                 parameters={"path": {"type": "string"}},
                 fn=file_type),
    ]
    for spec in specs:
        center.register_spec(spec, source=SOURCE_FUNCTION,
                             origin="ctf_tools", modes=modes)
    return len(specs)
