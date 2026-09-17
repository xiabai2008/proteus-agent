"""CTF 解题工具链测试（阶段二验收：3 道离线样例题端到端解出 flag）。

覆盖：
- 工具登记：RsaCtfTool / python 沙箱为 CLI，解码与文件识别为 function；
  每个工具都有 dangerous 标记与超时；模式可用性限定在 ctf-*
- CLI 参数渲染：自定义 flag（RsaCtfTool 的 -n/-e）与位置参数（python -c）
- 端到端：简单 RSA / base64 隐写 / 编码链，在 ctf-crypto 与 ctf-web 模式下解出
- 题面文件不含明文 flag（确保是真解出来的）
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "examples"))

import pytest

from eval_ctf_solve import build_challenges, solve  # noqa: E402
from penagent.modes import load_mode  # noqa: E402
from penagent.registry import (SOURCE_CLI, SOURCE_FUNCTION,  # noqa: E402
                               build_center)
from penagent.tools import ToolRegistry  # noqa: E402


@pytest.fixture(scope="module")
def challenges(tmp_path_factory):
    return build_challenges(tmp_path_factory.mktemp("ctf"))


# ----------------------------------------------------------------------
# 1. 工具登记与声明
# ----------------------------------------------------------------------
def test_ctf_tools_registered_with_source_and_modes():
    center = build_center()
    # 模式限定工具按 fail-closed 语义：不带模式查询看不到，故显式给 ctf-crypto
    entries = {e.name: e for e in center.discover(mode_id="ctf-crypto")}

    assert entries["rsactf_attack"].source == SOURCE_CLI
    assert entries["python_solve"].source == SOURCE_CLI
    for name in ("codec_decode", "codec_chain", "file_type"):
        assert entries[name].source == SOURCE_FUNCTION
        assert entries[name].origin == "ctf_tools"
    # 模式可用性：只在 ctf-* 可见
    for name in ("rsactf_attack", "python_solve", "codec_decode",
                 "codec_chain", "file_type"):
        assert set(entries[name].modes) == {"ctf-web", "ctf-crypto"}


def test_ctf_tools_declare_dangerous_and_timeout():
    center = build_center()
    specs = {e.name: e.spec for e in center.discover(mode_id="ctf-crypto")}

    assert specs["python_solve"].dangerous is True      # 任意代码执行
    assert specs["python_solve"].timeout == 60
    assert specs["rsactf_attack"].dangerous is False    # 纯本地计算
    assert specs["rsactf_attack"].timeout == 300
    assert specs["codec_decode"].dangerous is False


def test_ctf_tools_invisible_to_pentest_mode():
    center = build_center()
    pentest = center.build_registry(load_mode("pentest-standard"))
    assert "rsactf_attack" not in pentest.names()
    assert "python_solve" not in pentest.names()
    assert "codec_decode" not in pentest.names()

    ctf = center.build_registry(load_mode("ctf-crypto"))
    assert {"rsactf_attack", "python_solve", "codec_decode",
            "codec_chain", "file_type"} <= set(ctf.names())


def test_cli_arg_rendering_flags_and_positional():
    """RsaCtfTool 用单横线 -n/-e；python 沙箱用位置参数。"""
    from penagent.tools import ToolSpec

    rsa = ToolSpec(name="rsactf_attack", kind="cli",
                   command=["python", "-m", "RsaCtfTool", "{args}"],
                   parameters={"n": {"type": "string"}, "e": {"type": "string"},
                               "decrypt": {"type": "string"}},
                   arg_flags={"n": "-n", "e": "-e"})
    parts = ToolRegistry._cli_args(rsa, {"n": "123", "e": "65537",
                                         "decrypt": "456"})
    assert parts == ["-n", "123", "-e", "65537", "--decrypt", "456"]

    sandbox = ToolSpec(name="python_solve", kind="cli", positional=True,
                       parameters={"code": {"type": "string"}})
    assert ToolRegistry._cli_args(sandbox, {"code": "print(1)"}) == ["print(1)"]


def test_control_mode_denies_rsa_tool():
    """渗透模式挂载的注册表里没有 RSA 工具，调用必然失败（机制性）。"""
    center = build_center()
    pentest_registry = center.build_registry(load_mode("pentest-standard"))
    result = pentest_registry.execute("rsactf_attack", {"n": "1"})
    assert not result.ok and "未知工具" in result.error


# ----------------------------------------------------------------------
# 2. 样例题：题面不含明文 flag
# ----------------------------------------------------------------------
def test_challenge_files_hide_plaintext_flag(challenges):
    for cid, meta in challenges.items():
        text = meta["file"].read_text(encoding="utf-8")
        assert meta["flag"] not in text, f"{cid} 题面泄露了明文 flag"


# ----------------------------------------------------------------------
# 3. 端到端解题（真实工具 + 真实 flag 判定）
# ----------------------------------------------------------------------
@pytest.mark.parametrize("challenge_id", ["simple-rsa", "b64-stego",
                                          "encoding-chain"])
def test_solve_challenge_in_ctf_crypto(tmp_path, challenges, challenge_id):
    meta = challenges[challenge_id]
    result, agent = solve(tmp_path, challenge_id, meta, mode_id="ctf-crypto")

    assert result.outcome == "success", result.summary
    assert type(agent.verifier).__name__ == "FlagRegexVerifier"
    # flag 要么在收口结论里，要么在任务期间的工具输出里（判定器两者都扫）
    context = agent._mission_context(0)
    assert meta["flag"] in str(result.summary) or meta["flag"] in context


def test_solve_in_ctf_web_mode(tmp_path, challenges):
    """ctf-web 模式同样具备解题能力（两个 CTF 模式共用工具链）。"""
    meta = challenges["encoding-chain"]
    result, _ = solve(tmp_path, "encoding-chain", meta, mode_id="ctf-web")
    assert result.outcome == "success"
    assert meta["flag"] in str(result.summary)


def test_stego_verdict_comes_from_tool_output(tmp_path, challenges):
    """隐写题收口结论里没有 flag：判定靠扫描任务期间的工具输出。"""
    meta = challenges["b64-stego"]
    result, agent = solve(tmp_path, "b64-stego", meta, mode_id="ctf-crypto")

    assert result.outcome == "success"
    assert meta["flag"] not in str(result.summary)
    assert meta["flag"] in agent._mission_context(0)