"""测量工具测试（路线图 P2-3）：判定器 CLI + 会话存档取 flag。

三臂对照要算**假声明率**（声称解出但 checker 不接受），这需要两件工具都能被机检：

- `python -m penagent check-flag`：判定器 CLI（accept 退出 0 / reject 非 0）——
  给 A 臂与人工复核一个可复制的核对入口；
- `tools/dsh_session_flags.py`：A 臂（无内核）的读数——从会话存档抽最终 flag。

判据落在"退出码/替换语义/取哪条消息"上，不依赖真机 ELF（真机验收另做：拿
`libcloudseal.so` 核对正确 flag 退出 0、旧答案退出 1）。
"""
import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.cli import main

FLAG = "flag{f35b8ad6-2c51-4a85-93c0-0e6279347b1a}"


# ----------------------------------------------------------------------
# 1. check-flag：判定器 CLI
# ----------------------------------------------------------------------
def test_check_flag_missing_args_returns_json_error(capsys):
    assert main(["check-flag"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False and "需要 --elf 与 --flag" in payload["error"]


def test_check_flag_substitutes_flag_and_maps_verdict(monkeypatch, capsys):
    """`{flag}` 在参数里替换；accept → 退出码 0，reject/失败 → 非 0。"""
    import penagent.native_emu as native

    seen = {}

    def fake_native_emu(**kwargs):
        seen.update(kwargs)
        accept = kwargs["args"].startswith("str:flag{f35b")
        return {"ok": True, "verdict": "accept" if accept else "reject",
                "ret": 1 if accept else 0}

    monkeypatch.setattr(native, "native_emu", fake_native_emu)

    code = main(["check-flag", "--elf", "checker.so", "--func", "Check",
                 "--args", "str:{flag},len", "--flag", FLAG])
    assert code == 0
    assert seen["args"] == f"str:{FLAG},len"          # 占位符替换
    assert seen["elf"] == "checker.so" and seen["func"] == "Check"
    assert json.loads(capsys.readouterr().out)["verdict"] == "accept"

    code = main(["check-flag", "--elf", "checker.so",
                 "--args", "str:{flag},len", "--flag", "flag{deadbeef}"])
    assert code == 1                                   # reject → 非 0
    capsys.readouterr()

    def broken(**kwargs):
        return {"ok": False, "error": "符号不存在"}

    monkeypatch.setattr(native, "native_emu", broken)
    assert main(["check-flag", "--elf", "x.so", "--flag", FLAG]) == 1
    capsys.readouterr()


# ----------------------------------------------------------------------
# 2. 会话存档取 flag（A 臂测量）
# ----------------------------------------------------------------------
def _load_tool():
    path = PROJECT_ROOT / "tools" / "dsh_session_flags.py"
    spec = importlib.util.spec_from_file_location("dsh_session_flags", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_final_flags_prefers_last_assistant_message():
    tool = _load_tool()
    rows = [
        {"type": "assistant/message", "data": {"role": "assistant",
                                              "content": f"先试 {FLAG}"}},
        {"type": "tool/result", "data": {"output": "flag{ignored-in-tool}"}},
        {"type": "assistant/message", "data": {"role": "assistant",
                                              "content": "答案是 flag{deadbeef}"}},
    ]
    flags = tool.final_flags(rows)
    assert flags["final"] == ["flag{deadbeef}"]        # 最终回复优先
    assert FLAG in flags["all"]                        # 过程里出现过的另存
    assert "flag{ignored-in-tool}" not in flags["all"]  # 工具输出不算"它说的"


def test_check_flag_runs_argv_without_shell():
    """`--check` 按 argv 列表执行（不经 shell）：参数里有分号也不会被当成命令分隔。"""
    tool = _load_tool()
    verdict, _ = tool.check_flag(
        "flag{x}", [sys.executable, "-c",
                    "import sys; sys.exit(0 if 'flag{x}' in sys.argv[-1] else 3)",
                    "{flag}"])
    assert verdict == "ACCEPT"

    verdict, _ = tool.check_flag("flag{y}", [sys.executable, "-c",
                                             "import sys; sys.exit(1)"])
    assert verdict == "REJECT"


def test_read_archive_roundtrip(tmp_path):
    zstd = pytest.importorskip("zstandard",
                               reason="读 DSH 存档需要 zstandard（可选依赖）")
    tool = _load_tool()
    rows = [{"type": "session", "id": "s1"},
            {"type": "assistant/message",
             "data": {"role": "assistant", "content": "见 flag{a-b}"}}]
    body = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
    # 真机布局：<root>/<工作区>/<会话目录>/session.v4.jsonl.zstd
    archive = tmp_path / "羊城杯" / "session-x" / "session.v4.jsonl.zstd"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(zstd.ZstdCompressor().compress(body.encode("utf-8")))

    loaded = tool.read_archive(archive)
    assert len(loaded) == 2 and loaded[0]["id"] == "s1"
    assert tool.final_flags(loaded)["final"] == ["flag{a-b}"]
    found = tool.find_session("x", tmp_path)          # 短号与 session- 前缀都收
    assert found == archive
