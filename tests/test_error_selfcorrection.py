"""错误文本自纠正判据（路线图 P1-4）。

原则：**模型能一步自我纠正的错误，必须带上"可用项/候选/hint"**——只说
"找不到 / 不支持 / 不存在"的错误，模型只能猜第二遍（实测代价：一次 CTF 会话
里 60 步预算耗尽在重复同一个错路径上，见 R-38；模式名写错只回"已查找 <目录>"
那次也一样，见 R-45）。

本文件把这条原则变成**机检**：把一批"模型真会踩到"的错误路径逐个触发，断言
每条消息里至少出现一个自纠正标记（可用 / 候选 / 仅 / hint / 已尝试 / 最近）。
新增工具时照着补一行即可——判据落在文案协议上，不锁具体措辞。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

MARKERS = ("可用", "候选", "仅", "hint", "已尝试", "最近", "试", "允许")


def _messages(out) -> str:
    """把工具返回（dict 或 str）里的错误信息拼成一段文本。"""
    if isinstance(out, str):
        return out
    parts = [str(out.get(k, "")) for k in ("error", "hint", "note", "hint_text")]
    parts.append(json.dumps(out, ensure_ascii=False))
    return "\n".join(parts)


def _assert_selfcorrecting(text: str, where: str) -> None:
    assert any(m in text for m in MARKERS), (
        f"{where} 的错误文案不含自纠正标记：{text[:200]}")


@pytest.fixture()
def data(tmp_path, monkeypatch) -> Path:
    from penagent import sandbox as sb

    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setattr(sb, "_data_root", str(root))
    return root


def test_codec_errors_list_supported_codecs():
    from penagent.ctf_tools import codec_chain, codec_decode

    _assert_selfcorrecting(_messages(codec_decode("abc", "base99")),
                           "codec_decode(未知 codec)")
    _assert_selfcorrecting(_messages(codec_chain("616263", "hex,base99")),
                           "codec_chain(链里有未知 codec)")


def test_file_errors_are_actionable(data):
    from penagent.file_tools import file_edit, file_read, file_write

    (data / "dir").mkdir()
    (data / "dir" / "known.txt").write_text("x", encoding="utf-8")
    _assert_selfcorrecting(_messages(file_read("dir/missing.txt")),
                           "file_read(文件不存在)")
    _assert_selfcorrecting(_messages(file_read("/etc/passwd")),
                           "file_read(越界)")
    _assert_selfcorrecting(_messages(file_write("session-scope.json", "x")),
                           "file_write(写状态文件)")
    _assert_selfcorrecting(_messages(file_edit("dir/missing.txt", "a", "b")),
                           "file_edit(文件不存在)")


def test_native_emu_errors_are_actionable(tmp_path):
    from penagent.native_emu import native_emu

    (tmp_path / "x.so").write_bytes(b"not an elf")
    _assert_selfcorrecting(_messages(native_emu(elf=str(tmp_path / "x.so"))),
                           "native_emu(非 ELF)")
    _assert_selfcorrecting(_messages(native_emu(elf="/nope.so")),
                           "native_emu(文件不存在)")


def test_mode_and_scope_errors_are_actionable():
    from penagent.agent import Policy
    from penagent.modes import load_mode

    try:
        load_mode("ghost-mode")
        raise AssertionError("应该抛 ModeError")
    except Exception as exc:                       # noqa: BLE001 - 只看文案
        _assert_selfcorrecting(str(exc), "load_mode(未知模式)")

    policy = Policy(allowed_targets=["127.0.0.1"])
    spec = type("S", (), {"dangerous": False, "network": False})()
    ok, reason = policy.check("http_raw", spec, {"url": "https://evil.example/"})
    assert ok is False
    _assert_selfcorrecting(reason, "Policy(越界目标)")

    mode = load_mode("ctf-reverse")
    denied = Policy(allowed_targets=["127.0.0.1"], authorize=True, mode=mode)
    ok, reason = denied.check("nuclei_scan", spec,
                              {"target": "http://127.0.0.1/"})
    assert ok is False
    _assert_selfcorrecting(reason, "Policy(被模式禁用)")


def test_report_gen_errors_are_actionable(tmp_path):
    from penagent.builtin_tools import report_gen

    bad = report_gen(mission_id="m1", format="xml", data_dir=str(tmp_path))
    assert bad["ok"] is False
    _assert_selfcorrecting(str(bad.get("error", "")), "report_gen(未知 format)")
    out = report_gen(mission_id="m1", data_dir=str(tmp_path))
    _assert_selfcorrecting(_messages(out), "report_gen(任务不存在)")


def test_http_raw_rejects_method_with_options(raw_server=None):
    from penagent.builtin_tools import http_raw

    out = http_raw("http://127.0.0.1:1/", method="PUT")
    assert "error" in out
    _assert_selfcorrecting(_messages(out), "http_raw(不支持的方法)")


def test_mcp_unknown_method_lists_methods(tmp_path):
    from penagent.mcp import PentestMCPServer

    server = PentestMCPServer(data_dir=str(tmp_path / "data"))
    raw = server.handle_line(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/frob"}))
    payload = json.loads(raw) if isinstance(raw, str) else raw
    _assert_selfcorrecting(json.dumps(payload, ensure_ascii=False),
                           "MCP(未知方法)")
