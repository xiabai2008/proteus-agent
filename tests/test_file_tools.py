"""内核文件工具（file_read / file_write / file_edit）测试。

路线图 P1-1：CLI 路径此前**没有通用文件读写**（只有 file_type 预览与容器内
python_solve 整段重发），"写脚本→跑→改→再跑"这条最基本的循环走不通。本文件的
判据分三层：

- **循环**：写 → 读 → 改 → 读，内容与 sha256 对得上；
- **边界（硬规则 1/3 的延伸）**：作用域限 data 目录（越界拒绝、/samples 视角可用），
  状态与审计文件（授权/模式/证据链/作战记录/技能库）**只读**；
- **编辑语义**：默认唯一匹配（0 次报未找到、多次报不唯一且不改），`count` 显式多替换。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent import sandbox as sb
from penagent.file_tools import file_edit, file_read, file_write
from penagent.modes import load_mode
from penagent.registry import build_center


@pytest.fixture()
def data(tmp_path, monkeypatch) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setattr(sb, "_data_root", str(root))
    return root


# ----------------------------------------------------------------------
# 1. 写 → 读 → 改 → 读
# ----------------------------------------------------------------------
def test_write_read_edit_roundtrip(data):
    script = "print('v1')\n"
    written = file_write("cloudseal/solve.py", script)
    assert written["path"] == "cloudseal/solve.py"        # 父目录自动创建
    assert written["bytes"] == len(script)
    assert (data / "cloudseal" / "solve.py").read_text(encoding="utf-8") \
        == script

    read = file_read("cloudseal/solve.py")
    assert read["text"] == script and read["truncated"] is False
    assert read["lines"] == 1 and read["size"] == len(script)

    edited = file_edit("cloudseal/solve.py", "'v1'", "'v2'")
    assert edited["replaced"] == 1
    assert file_read("cloudseal/solve.py")["text"] == "print('v2')\n"
    # sha256 让"这次写入的内容"事后可核对
    assert edited["sha256"] == file_read("cloudseal/solve.py")["sha256"]


def test_write_append_and_container_view(data):
    file_write("/samples/notes/a.txt", "one\n")
    file_write("/samples/notes/a.txt", "two\n", append=True)
    assert file_read("/samples/notes/a.txt")["text"] == "one\ntwo\n"


def test_read_binary_returns_hex_preview(data):
    (data / "blob.bin").write_bytes(b"\x00\x01\x02PK\x03\x04" + b"x" * 40)
    out = file_read("blob.bin")
    assert out["binary"] is True and "text" not in out
    assert out["preview_hex"].startswith("00 01 02 50 4b")


def test_read_truncates_and_greps_full_content(data):
    body = "".join(f"line {i}: filler\n" for i in range(500))
    body += "SECRET_MARKER_HERE\n"
    file_write("big.txt", body)

    out = file_read("big.txt", max_chars=300)
    assert out["truncated"] is True and len(out["text"]) == 300
    assert "正文已截断" in out["note"]
    # 过小的 max_chars 按 256 收口（与 http_raw 同口径）
    assert len(file_read("big.txt", max_chars=10)["text"]) == 256

    got = file_read("big.txt", max_chars=300, grep="SECRET_\\w+")
    assert got["grep"]["matches"] == ["SECRET_MARKER_HERE"]   # 绕过截断
    assert got["grep"]["scanned_chars"] > 300


def test_read_missing_file_lists_candidates(data):
    file_write("dir/known.txt", "x")
    out = file_read("dir/unknown.txt")
    assert "不存在" in out["error"]
    assert out["candidates"] == ["known.txt"]      # 错误能自我纠正


# ----------------------------------------------------------------------
# 2. 边界：作用域与写保护
# ----------------------------------------------------------------------
def test_paths_outside_data_are_refused(data, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    assert "越界" in file_read(str(outside))["error"]
    assert "越界" in file_read("../outside.txt")["error"]
    assert "越界" in file_write("../escape.txt", "x")["error"]
    assert not (tmp_path / "escape.txt").exists()


def test_state_and_audit_files_are_read_only(data):
    """授权/模式/证据链/作战记录/技能库：写拒绝，读允许。"""
    (data / "session-scope.json").write_text(
        json.dumps({"targets": ["127.0.0.1"]}), encoding="utf-8")
    (data / "session-mode-ctf-crypto.json").write_text(
        json.dumps({"mode": "ctf-crypto"}), encoding="utf-8")
    (data / "chain.jsonl").write_text("", encoding="utf-8")
    (data / "skills" / "ctf-crypto").mkdir(parents=True)
    (data / "skills" / "ctf-crypto" / "s.json").write_text("{}", encoding="utf-8")

    for rel, marker in (("session-scope.json", "会话状态文件"),
                        ("session-mode-ctf-crypto.json", "会话状态文件"),
                        ("chain.jsonl", "证据链"),
                        ("skills/ctf-crypto/s.json", "知识库")):
        out = file_write(rel, "tampered")
        assert "拒绝写入" in out["error"] and marker in out["error"], rel
        assert file_edit(rel, "a", "b")["error"].startswith("拒绝写入"), rel

    # 读不受限：审计与技能是可读的
    assert "targets" in file_read("session-scope.json")["text"]
    assert file_read("skills/ctf-crypto/s.json")["text"] == "{}"


# ----------------------------------------------------------------------
# 3. 编辑语义
# ----------------------------------------------------------------------
def test_edit_requires_unique_match(data):
    file_write("s.py", "x = 1\ny = 1\n")
    dup = file_edit("s.py", "= 1", "= 2")
    assert "不唯一" in dup["error"] and "count=2" in dup["hint"]
    assert file_read("s.py")["text"] == "x = 1\ny = 1\n"      # 未做修改

    many = file_edit("s.py", "= 1", "= 2", count=2)
    assert many["replaced"] == 2
    assert file_read("s.py")["text"] == "x = 2\ny = 2\n"

    missing = file_edit("s.py", "not-there", "x")
    assert "未出现" in missing["error"] and "hint" in missing

    assert file_edit("s.py", "", "x")["error"].startswith("old 不能为空")


def test_write_accepts_string_booleans(data):
    """模型常把布尔写成字符串（"true"/"false"）——按真值语义收。"""
    file_write("a.txt", "1")
    file_write("a.txt", "2", append="true")
    assert file_read("a.txt")["text"] == "12"
    file_write("b.txt", "1", append="false")
    file_write("b.txt", "2", append="false")
    assert file_read("b.txt")["text"] == "2"


# ----------------------------------------------------------------------
# 4. 工具面：可见性与档位
# ----------------------------------------------------------------------
def test_file_tools_registered_in_ctf_modes_only():
    center = build_center()
    entries = {e.name: e for e in center.discover(mode_id="ctf-crypto")}
    for name in ("file_read", "file_write", "file_edit"):
        assert name in entries and entries[name].origin == "ctf_tools"
        assert set(entries[name].modes) == {"ctf-web", "ctf-crypto",
                                           "ctf-reverse"}
    # 都不是 dangerous：沙箱判据里 "dangerous ⇒ 必须进容器"，而 function 工具
    # 进不了容器；写操作的摩擦由模式 permission 档位承担（见下一条用例）
    for name in ("file_read", "file_write", "file_edit"):
        assert entries[name].spec.dangerous is False

    pentest = center.build_registry(load_mode("pentest-standard"))
    assert "file_read" not in pentest.names()


def test_write_needs_confirm_tier(data):
    """写工具的摩擦在档位：未授权会话被拒，授权后可写（mode require_confirm）。"""
    from penagent.agent import Policy

    mode = load_mode("ctf-reverse")
    spec = type("S", (), {"name": "file_write", "dangerous": False,
                          "network": False})()
    denied = Policy(allowed_targets=["127.0.0.1"], mode=mode)
    ok, reason = denied.check("file_write", spec, {"path": "x.txt"})
    assert ok is False and "待人工确认" in reason

    allowed = Policy(allowed_targets=["127.0.0.1"], authorize=True, mode=mode)
    ok, _ = allowed.check("file_write", spec, {"path": "x.txt"})
    assert ok is True
