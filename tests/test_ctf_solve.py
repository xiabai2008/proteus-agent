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
import json
import struct
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


# ----------------------------------------------------------------------
# 可选工具链守卫（2026-10-01 CI 实测补）
#
# CTF 工具链里有几个工具依赖**可选依赖**：`checksec_bin` 要 pwntools 的 `pwn`，
# `rsactf_attack` 要 RsaCtfTool 包，其余扫描器要 PENTEST_TOOLS 工具库。它们都
# 不在 requirements.txt 里（与 torch / unicorn 同为可选依赖，见 AGENTS.md 硬
# 规则 5）。内核的既定语义是"不可用不注册"——本机没装就注册不出来，这不是缺陷。
#
# 于是"环境缺依赖"不该表现为**失败**（那会掩盖真回归），也不该表现为**静默**
# 通过（那会假装覆盖过）。照 test_m3.py 的外部工具口径做显式 skip，理由里写清
# 缺什么、怎么装。
# ----------------------------------------------------------------------
def _require_checksec_bin():
    """`checksec_bin` 需要 `pwn`（pwntools）才能注册。"""
    if "checksec_bin" not in {e.name for e in build_center().all_entries()}:
        pytest.skip("pwntools 未安装（可选依赖，提供 `pwn checksec`），"
                    "checksec_bin 未注册。安装：pip install pwntools")


def _require_rsactftool():
    """参考解的分档里程碑要 RsaCtfTool **真跑出明文**才算解出。"""
    import importlib.util

    if importlib.util.find_spec("RsaCtfTool") is None:
        pytest.skip("RsaCtfTool 未安装（可选依赖），参考解覆盖不到 decrypt "
                    "里程碑。安装：pip install RsaCtfTool")


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
    for name in ("codec_decode", "codec_chain", "file_type", "native_emu"):
        assert entries[name].source == SOURCE_FUNCTION
        assert entries[name].origin == "ctf_tools"
    # 模式可用性：只在 ctf-* 可见
    ctf_modes = {"ctf-web", "ctf-crypto", "ctf-reverse"}
    for name in ("rsactf_attack", "python_solve", "codec_decode",
                 "codec_chain", "file_type", "native_emu", "file_read",
                 "file_write", "file_edit"):
        assert set(entries[name].modes) == ctf_modes


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
# P1-2（2026-09-24）：pwn 题第一步——ELF 保护检查进 CTF 工具面
# ----------------------------------------------------------------------
def test_checksec_declares_container_requirement():
    """`checksec_bin` 声明 docker 档：容器不可用时被拒，不回落宿主直跑。"""
    _require_checksec_bin()
    from penagent.sandbox import SandboxPolicy, tool_needs_isolation
    from penagent.tools import ToolRegistry

    sys.path.insert(0, str(PROJECT_ROOT / "tests"))
    from test_sandbox import StubRunner  # noqa: E402

    center = build_center()
    entries = {e.name: e for e in center.discover(mode_id="ctf-crypto")}
    spec = entries["checksec_bin"].spec
    assert spec.sandbox == "docker"
    assert spec.network is False
    assert tool_needs_isolation(spec) is True
    # 命令形态：pwn checksec <file>（单参数按位置传，没有 shell 拼接）
    assert ToolRegistry._cli_args(spec, {"file": "/samples/chall"}) == \
        ["/samples/chall"]

    registry = ToolRegistry(sandbox=SandboxPolicy(
        "docker", runner=StubRunner(available=False)))
    registry.register(spec)
    refused = registry.execute("checksec_bin", {"file": "/samples/chall"})
    assert not refused.ok and "容器" in refused.error


def test_checksec_is_visible_in_ctf_and_hidden_in_pentest():
    """工具面按模式裁剪：CTF 会话看得见，渗透会话看不见。"""
    center = build_center()
    ctf = {e.name for e in center.discover(mode_id="ctf-web")}
    pentest = {e.name for e in center.discover(mode_id="pentest-standard")}
    # "渗透面看不见"与依赖装没装无关（模式归属写在 ctf_tools.json 的 modes
    # 里），先把它钉死——这半边在任何环境都有效，不能因为缺 pwntools 就丢
    assert "checksec_bin" not in pentest
    # "CTF 面看得见"依赖工具真的注册成功，缺 pwntools 时这里如实跳过
    _require_checksec_bin()
    assert "checksec_bin" in ctf


# ----------------------------------------------------------------------
# 路径口径统一（R-38，2026-09-24 实测）
#
# 同一个 CTF 工具面里混着两种视角：容器化 MCP 工具（binwalk/yara/capa）与
# checksec_bin 用 `/samples/...`（宿主 data 目录在容器内的只读挂载点），宿主侧
# file_type 却按 cwd 解析。实测一次会话里模型照 `/samples/...` 调 file_type，
# 连失败 57 次、60 步预算耗尽。
# ----------------------------------------------------------------------
def test_file_type_accepts_container_samples_path(tmp_path, monkeypatch):
    """/samples/... 前缀映射到宿主 data 目录——两种视角等价。"""
    from penagent import sandbox as sb
    from penagent.ctf_tools import file_type

    root = tmp_path / "data"
    (root / "eval-ctf").mkdir(parents=True)
    (root / "eval-ctf" / "encoding-chain.txt").write_text(
        "# encoded challenge", encoding="utf-8")
    monkeypatch.setattr(sb, "_data_root", str(root))

    out = file_type("/samples/eval-ctf/encoding-chain.txt")
    assert "error" not in out
    assert out["type"] == "text" and "encoded challenge" in out["preview"]


def test_file_type_relative_path_falls_back_to_data_root(tmp_path, monkeypatch):
    """相对路径先按 cwd 解析，未命中再试 data 目录之下（模型常省掉 data/）。"""
    from penagent import sandbox as sb
    from penagent.ctf_tools import file_type

    root = tmp_path / "data"
    (root / "eval-ctf").mkdir(parents=True)
    (root / "eval-ctf" / "x.txt").write_text("hello", encoding="utf-8")
    monkeypatch.setattr(sb, "_data_root", str(root))

    out = file_type("eval-ctf/x.txt")
    assert "error" not in out and out["type"] == "text"


def test_file_type_error_is_actionable(tmp_path, monkeypatch):
    """失败信息必须可操作：已尝试路径 / cwd / /samples 映射目标 / 同目录候选。

    只说"文件不存在"四个字，模型只能反复重试同一个错路径——实测就是这样
    烧掉整轮预算的。
    """
    from penagent import sandbox as sb
    from penagent.ctf_tools import file_type

    root = tmp_path / "data"
    (root / "eval-ctf").mkdir(parents=True)
    (root / "eval-ctf" / "real.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(sb, "_data_root", str(root))

    out = file_type("/samples/eval-ctf/typo.txt")
    err = out["error"]
    assert "文件不存在" in err
    assert "已尝试" in err and "cwd=" in err and "/samples 映射到" in err
    assert "real.txt" in out["candidates"]        # 候选帮模型一次纠正


def _minimal_elf() -> bytes:
    """结构合法的最小 64 位 ELF（仅文件头，无程序头 / 节表）。

    为什么要按字节构造：沙箱镜像里没有编译器（实测 gcc / cc / as / ld 全无），
    没法 `docker run ... gcc` 现编一个。但**必须是合法 ELF**——本用例早先写的是
    `b"\\x7fELF" + b"\\x00" * 124`，EI_CLASS 落成 0x00，`pwn checksec` 直接
    `Invalid EI_CLASS` 退出，`RELRO` 断言根本走不到；而这条用例一直被
    "Docker 不可用即 skip"掩盖，直到 R-43 复核对齐容器时才暴露。
    """
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8   # 64 位 / 小端 / v1
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,           # e_type    = ET_EXEC
        0x3E,        # e_machine = EM_X86_64
        1,           # e_version
        0x400000,    # e_entry
        64,          # e_phoff（紧随文件头）
        0,           # e_shoff（无节表）
        0,           # e_flags
        64,          # e_ehsize
        56,          # e_phentsize
        0,           # e_phnum
        64,          # e_shentsize
        0,           # e_shnum
        0,           # e_shstrndx
    )
    return ident + header


def test_checksec_runs_in_sandbox_image(monkeypatch):
    """真跑一次（Docker + 专用镜像就绪时；否则 skip，与容器类用例同口径）。

    用**生产规格**（`ctf_tools.json` 的 checksec_bin）而不是内联副本：本条的
    价值就在"`/samples` 挂载约定 + 生产命令行在容器里真跑得通"（R-43 补的挂载
    正是这条描述承诺的）；内联副本一旦与生产漂移，覆盖的就是假路径。判据取
    checksec 标准输出里的 RELRO 字段。
    """
    import sys
    from pathlib import Path

    from penagent import sandbox as sb
    from penagent.registry import build_center
    from penagent.sandbox import SandboxPolicy
    from penagent.tools import ToolRegistry

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_sandbox import _sandbox_image_or_skip

    runner = _sandbox_image_or_skip()
    repo = Path(__file__).resolve().parent.parent
    samples = repo / "data" / "ctf-demo"
    samples.mkdir(parents=True, exist_ok=True)
    (samples / "checksec-demo").write_bytes(_minimal_elf())
    # 显式指向仓库 data——`/samples` 的宿主侧来源；不依赖进程 cwd
    monkeypatch.setattr(sb, "_data_root", str(repo / "data"))

    spec = {e.name: e for e in build_center().discover(
        mode_id="ctf-crypto")}["checksec_bin"].spec
    registry = ToolRegistry(sandbox=SandboxPolicy("docker", runner=runner))
    registry.register(spec)
    result = registry.execute("checksec_bin",
                              {"file": "/samples/ctf-demo/checksec-demo"})
    assert result.ok, result.error
    assert "RELRO" in str(result.output)


def test_rsactf_attack_review_locks_host_direct_tier():
    """F-E2E-3 定档契约：rsactf_attack 保持宿主直跑，人工把关由权限档位承担。

    静默改档会同时破坏两条既有保证：
    1) Docker-free 环境的 CTF 解题链路——**默认镜像 python:3.12-slim 内不含
       RsaCtfTool**（专用镜像 proteus-sandbox 才有，且需显式配置
       PENTEST_DOCKER_IMAGE），提权为隔离档即该工具在未配置环境下不可用
       （评测将退回 Docker 依赖）；
    2) 纯本地计算的定位——离线数学攻击、参数经 flag 渲染无注入面。
    改档必须连同 docs/端到端实战演练.md 的 F-E2E-3 处置一起重新评审。

    注：原措辞为"沙箱镜像内没有 RsaCtfTool"。R-15 建了专用镜像后该表述不再
    准确（镜像里有了），但**结论不变**——约束从"镜像内没有"变成"需专用镜像
    且需显式配置"，Docker-free 环境仍跑不了。
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


# ----------------------------------------------------------------------
# P2-2：分档评分（里程碑由题集真值派生，判据落在工具输出上）
#
# 背景（Cybench 的启发）：二值评分在 33 题规模上信息量太低——"8/33" 看不出
# 是"全流程都在、最后差一步"还是"根本没入门"。里程碑给的是"差多少"。
# ----------------------------------------------------------------------
def _fresh_root(tmp_path):
    root = tmp_path / "graded"
    root.mkdir(parents=True, exist_ok=True)
    return root


def test_milestone_shape_per_category(tmp_path, challenges, host_direct_sandbox):
    """里程碑条数由类别与题面结构决定（不手写 33 份）。"""
    from eval_ctf_solve import milestones_for

    read = lambda meta: [{"tool": "file_type", "ok": True,
                          "args": {"path": str(meta["file"])}}]

    single = milestones_for("enc-b64", challenges["enc-b64"], read(challenges["enc-b64"]),
                            verified=False)
    multi = milestones_for("enc-hex-b64", challenges["enc-hex-b64"],
                           read(challenges["enc-hex-b64"]), verified=False)
    stego = milestones_for("b64-stego", challenges["b64-stego"],
                           read(challenges["b64-stego"]), verified=False)
    rsa = milestones_for("simple-rsa", challenges["simple-rsa"],
                         read(challenges["simple-rsa"]), verified=False)

    assert [m["id"] for m in single] == ["inspect", "flag"]          # 单层无中间态
    assert [m["id"] for m in multi] == ["inspect", "peel-outer", "flag"]
    assert [m["id"] for m in stego] == ["inspect", "locate-block", "flag"]
    assert [m["id"] for m in rsa] == ["inspect", "decrypt", "flag"]
    # 只读了题面：首条完成、其余未完成
    assert [m["ok"] for m in multi] == [True, False, False]


def test_grade_discriminates_partial_progress():
    """分档必须能区分"差一步"与"没入门"——这是它存在的理由。"""
    from eval_ctf_solve import encode_chain, grade_run

    meta = {"file": "x.txt", "flag": "flag{abc}", "category": "encoding",
            "chain": ["hex", "base64"]}
    read = [{"tool": "file_type", "ok": True, "args": {"path": "x.txt"}}]
    # 剥掉外层后的中间态必须真的出现在**工具输出**里（判据落在输出上）
    intermediate = encode_chain("flag{abc}", ["hex"])
    peel = read + [{"tool": "codec_chain", "ok": True,
                    "args": {"data": "aGk="},
                    "output": json.dumps({"result": intermediate})}]

    nothing = grade_run("t", meta, [], verified=False)
    half = grade_run("t", meta, read, verified=False)
    almost = grade_run("t", meta, peel, verified=False)
    done = grade_run("t", meta, peel, verified=True)

    assert (nothing["subtask"], half["subtask"], almost["subtask"],
            done["subtask"]) == ("0/3", "1/3", "2/3", "3/3")
    assert nothing["subtask_score"] < almost["subtask_score"] < 1.0
    # 前三个都没有收口；只有最后一个 unguided 与 subtask_guided 同时为真
    assert not any(x["unguided"] for x in (nothing, half, almost))
    assert done["unguided"] and done["subtask_guided"]


def test_read_source_matches_windows_paths(tmp_path, host_direct_sandbox):
    """路径判据不能用 f-string 打 dict（反斜杠会被转义成 `\\\\`）——实测踩中。"""
    from eval_ctf_solve import _read_source

    win = r"C:\Users\x\AppData\Local\Temp\enc-b64.txt"
    calls = [{"tool": "file_type", "ok": True, "args": {"path": win}}]
    assert _read_source(calls, win) is True
    assert _read_source(calls, r"C:\other\path.txt") is False
    # 被拦下的调用不算"读过"
    blocked = [{"tool": "file_type", "ok": True, "blocked": True,
                "args": {"path": win}}]
    assert _read_source(blocked, win) is False


def test_all_challenges_score_full_on_the_reference_path(tmp_path, challenges,
                                                         host_direct_sandbox):
    """脚本化参考解在 33 题上都应拿满分档——分档与二值口径不矛盾。"""
    from eval_ctf_solve import solve_graded

    # 参考解要真调工具：crypto 题的 decrypt 里程碑判据是"明文出现在工具输出
    # 里"，RsaCtfTool 没装就必然 2/3。本机 vs CI 的差异必须在守卫里说清，
    # 否则 CI 上看不出这是"环境缺依赖"还是"分档口径坏了"。
    _require_rsactftool()
    root = _fresh_root(tmp_path)
    lagging = {}
    for cid, meta in build_challenges(root).items():
        out = solve_graded(root, cid, meta, mode_id="ctf-crypto")
        grade = out["grade"]
        if grade["subtask_score"] < 1.0:
            lagging[cid] = grade["subtask"]
    assert lagging == {}, f"这些题没能拿满分档：{lagging}"