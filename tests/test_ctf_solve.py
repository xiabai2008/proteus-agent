"""CTF 解题工具链测试（阶段二验收：离线题集端到端解出 flag）。

覆盖：
- 工具登记：RsaCtfTool / python 沙箱为 CLI，解码与文件识别为 function；
  每个工具都有 dangerous 标记与超时；模式可用性限定在 ctf-*
- CLI 参数渲染：自定义 flag（RsaCtfTool 的 -n/-e）与位置参数（python -c）
- 题集结构：id 唯一、类别齐全（encoding/stego/crypto）、规模下限
- 端到端：全部题目在 ctf-crypto 与 ctf-web 模式下解出
- 题面文件不含明文 flag（确保是真解出来的）

题集规模由 `eval_ctf_solve` 的声明式规格决定——加题只需改那边的 `*_CASES`
表，本文件的 parametrize 从 `challenge_ids()` 派生，自动覆盖新题。
"""
import sys
import urllib.parse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "examples"))

import pytest

from eval_ctf_solve import (build_challenges, challenge_ids,  # noqa: E402
                            solve)
from penagent.modes import load_mode  # noqa: E402
from penagent.registry import (SOURCE_CLI, SOURCE_FUNCTION,  # noqa: E402
                               build_center)
from penagent.tools import ToolRegistry  # noqa: E402


@pytest.fixture(scope="module")
def challenges(tmp_path_factory):
    return build_challenges(tmp_path_factory.mktemp("ctf"))


# host_direct_sandbox fixture 见 conftest.py：出厂 ctf-* 模式是 sandbox: docker，
# 解题用例显式注入 local 档以保持链路真跑（无 Docker 时的拒绝行为由
# test_sandbox.py 的用例钉住）。


@pytest.fixture(autouse=True)
def _restore_chat_json():
    """隔离全局替换：examples/eval_ctf_solve.solve() 会把 agent.chat_json 换成
    脚本化决策且**不还原**（那是评测脚本的行为，本文件不改它）。不隔离的话，
    同一进程里排在后面的用例会拿到一个"从空列表 pop"的假决策函数。
    """
    import penagent.agent as agent_mod

    original = agent_mod.chat_json
    yield
    agent_mod.chat_json = original


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


def test_rsactf_attack_review_locks_host_direct_tier():
    """F-E2E-3 定档契约：rsactf_attack 保持宿主直跑，人工把关由权限档位承担。

    静默改档会同时破坏两条既有保证：
    1) Docker-free 环境的 CTF 解题链路——沙箱镜像内没有 RsaCtfTool，
       提权为隔离档即该工具不可用（评测将退回 Docker 依赖）；
    2) 纯本地计算的定位——离线数学攻击、参数经 flag 渲染无注入面。
    改档必须连同 docs/端到端实战演练.md 的 F-E2E-3 处置一起重新评审。
    """
    center = build_center()
    specs = {e.name: e.spec for e in center.discover(mode_id="ctf-crypto")}
    assert specs["rsactf_attack"].dangerous is False
    assert specs["rsactf_attack"].sandbox == ""       # 无强制隔离声明
    mode = load_mode("ctf-crypto")
    assert mode.permission.level_for("rsactf_attack") == "ask"   # 人工确认
    assert mode.sandbox == "docker"                   # python_solve 隔离档不变


# ----------------------------------------------------------------------
# 2. 样例题：题面不含明文 flag
# ----------------------------------------------------------------------
def test_challenge_files_hide_plaintext_flag(challenges):
    for cid, meta in challenges.items():
        text = meta["file"].read_text(encoding="utf-8")
        assert meta["flag"] not in text, f"{cid} 题面泄露了明文 flag"


# ----------------------------------------------------------------------
# 2b. 题集结构（防止加题时写重 id / 漏类别 / 规模退化）
# ----------------------------------------------------------------------
def test_challenge_ids_unique_and_complete(challenges):
    ids = challenge_ids()
    assert len(ids) == len(set(ids)), "题集存在重复 id"
    assert set(ids) == set(challenges.keys()), "challenge_ids 与实际题集不一致"


def test_challenge_set_covers_all_categories(challenges):
    cats = {meta.get("category") for meta in challenges.values()}
    assert {"encoding", "stego", "crypto"} <= cats


def test_challenge_set_meets_scale_floor(challenges):
    """规模下限：3 道题不足以判断强弱（见 docs/评测骨架.md 第七节）。"""
    assert len(challenges) >= 30
    by_cat: dict[str, int] = {}
    for meta in challenges.values():
        by_cat[meta["category"]] = by_cat.get(meta["category"], 0) + 1
    assert by_cat["encoding"] >= 20, f"编码题仅 {by_cat.get('encoding', 0)} 道"
    assert by_cat["crypto"] >= 3, f"RSA 题仅 {by_cat.get('crypto', 0)} 道"


def test_encoding_cases_are_not_degenerate():
    """编码链不得含"对纯字母数字输出再 url 编码"这类空操作组合。

    空操作会让本题的实际难度退化成链中另一道题，白白占一个题位。
    """
    from eval_ctf_solve import ENCODING_CASES, _encode_once

    for cid, chain, _flag in ENCODING_CASES:
        for i in range(len(chain) - 1):
            step_in = chain[i + 1]
            probe = _encode_once("flag{abcdef0123456789}", chain[i])
            if step_in == "url":
                # url 编码只对含保留字符的输入有效（hex 输出全是 [0-9a-f]）
                assert probe != urllib.parse.quote(probe, safe=""), \
                    f"{cid}: {chain[i]} -> url 是空操作"


# ----------------------------------------------------------------------
# 3. 端到端解题（真实工具 + 真实 flag 判定）
# ----------------------------------------------------------------------
@pytest.mark.parametrize("challenge_id", challenge_ids())
def test_solve_challenge_in_ctf_crypto(tmp_path, challenges, challenge_id,
                                       host_direct_sandbox):
    """全部题集在 ctf-crypto 模式下可解（列表从题集规格派生，加题自动覆盖）。"""
    meta = challenges[challenge_id]
    result, agent = solve(tmp_path, challenge_id, meta, mode_id="ctf-crypto")

    assert result.outcome == "success", result.summary
    assert type(agent.verifier).__name__ == "FlagRegexVerifier"
    # flag 要么在收口结论里，要么在任务期间的工具输出里（判定器两者都扫）
    context = agent._mission_context(0)
    assert meta["flag"] in str(result.summary) or meta["flag"] in context


def test_solve_in_ctf_web_mode(tmp_path, challenges, host_direct_sandbox):
    """ctf-web 模式同样具备解题能力（两个 CTF 模式共用工具链）。"""
    meta = challenges["encoding-chain"]
    result, _ = solve(tmp_path, "encoding-chain", meta, mode_id="ctf-web")
    assert result.outcome == "success"
    assert meta["flag"] in str(result.summary)


def test_stego_verdict_comes_from_tool_output(tmp_path, challenges,
                                              host_direct_sandbox):
    """隐写题收口结论里没有 flag：判定靠扫描任务期间的工具输出。"""
    meta = challenges["b64-stego"]
    result, agent = solve(tmp_path, "b64-stego", meta, mode_id="ctf-crypto")

    assert result.outcome == "success"
    assert meta["flag"] not in str(result.summary)
    assert meta["flag"] in agent._mission_context(0)