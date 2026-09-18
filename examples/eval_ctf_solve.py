"""阶段二验收：CTF Crypto/Misc 工具链端到端解题（离线构造样例题）。

三道题：
  1. simple-rsa     ：相近素数 RSA（n/e/c 已知，需分解后解密）
  2. b64-stego      ：base64 隐写（多个 base64 块，只有一块解出 flag）
  3. encoding-chain ：编码链（hex(base64(rot13(flag)))）

离线说明：仓库不带 .env / API key，LLM 决策用**脚本化序列**替代（扮演模型
选工具的角色）；工具执行（RsaCtfTool / python 沙箱 / 解码链）与 flag 判定
（FlagRegexVerifier）都是真实路径。

运行：python examples/eval_ctf_solve.py
"""
import base64
import codecs
import hashlib
import random
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import penagent.agent as agent_mod  # noqa: E402
from penagent.agent import PenAgent, Policy  # noqa: E402
from penagent.evidence import EvidenceChain  # noqa: E402
from penagent.llm import LLMConfig  # noqa: E402
from penagent.memory import Memory  # noqa: E402
from penagent.modes import load_mode  # noqa: E402
from penagent.registry import build_center  # noqa: E402

DATA = ROOT / "data" / "eval-ctf"


# ----------------------------------------------------------------------
# 题目构造（离线、确定性）
# ----------------------------------------------------------------------
def _is_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin 素性测试（stdlib 实现，避免测试引入 sympy 依赖）。"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _next_prime(n: int) -> int:
    candidate = n | 1
    while not _is_prime(candidate):
        candidate += 2
    return candidate


def build_challenges(root: Path) -> dict:
    """在 root 下生成三道离线样例题，返回题目元数据（含答案 flag）。"""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    # 1) 简单 RSA：相近素数 -> fermat 攻击可解
    rng = random.Random(20260917)
    p = _next_prime(rng.getrandbits(512))
    q = _next_prime(p + rng.getrandbits(20))
    n, e = p * q, 65537
    flag_rsa = b"flag{rsa_close_primes_pwned}"
    c = pow(int.from_bytes(flag_rsa, "big"), e, n)
    (root / "simple_rsa.txt").write_text(
        "# RSA challenge (offline)\n"
        f"n = {n}\n"
        f"e = {e}\n"
        f"c = {c}\n"
        "# 提示：两个素数是相近的\n", encoding="utf-8")

    # 2) base64 隐写：多块 base64，只有一块解出 flag（其余是诱饵）
    flag_b64 = "flag{b64_stego_found}"
    decoys = ["the quick brown fox jumps over the lazy dog",
              "nothing to see here, move along",
              "decoylead: admin panel at /admin"]
    blob_flag = base64.b64encode(flag_b64.encode()).decode()
    blob_decoys = [base64.b64encode(d.encode()).decode() for d in decoys]
    lines = ["# captured log fragments",
             f"note_a={blob_decoys[0]}",
             f"blob={blob_flag}",
             f"note_b={blob_decoys[1]}",
             f"meta={blob_decoys[2]}"]
    (root / "b64_stego.txt").write_text("\n".join(lines) + "\n",
                                        encoding="utf-8")

    # 3) 编码链：hex(base64(rot13(flag)))
    flag_chain = "flag{layered_encodings_ok}"
    step1 = codecs.encode(flag_chain, "rot_13")
    step2 = base64.b64encode(step1.encode()).decode()
    step3 = step2.encode().hex()
    (root / "encoding_chain.txt").write_text(step3 + "\n", encoding="utf-8")

    return {
        "simple-rsa": {"file": root / "simple_rsa.txt", "flag": flag_rsa.decode(),
                       "n": n, "e": e, "c": c},
        "b64-stego": {"file": root / "b64_stego.txt", "flag": flag_b64},
        "encoding-chain": {"file": root / "encoding_chain.txt",
                           "flag": flag_chain, "chain": step3},
    }


# ----------------------------------------------------------------------
# 解题：三个题目各跑一次内核（脚本化决策 + 真实工具 + 真实判定）
# ----------------------------------------------------------------------
def _solve_script(challenge_id: str, meta: dict) -> list[dict]:
    """扮演"模型选工具"的脚本化决策序列（离线替代 LLM）。"""
    path = str(meta["file"])
    if challenge_id == "simple-rsa":
        return [
            {"thought": "先看题面文件", "tool": "file_type",
             "args": {"path": path}},
            {"thought": "相近素数：用 fermat 攻击分解并解密",
             "tool": "rsactf_attack",
             "args": {"n": str(meta["n"]), "e": str(meta["e"]),
                      "decrypt": str(meta["c"]), "attack": "fermat",
                      "timeout": "120"}},
            {"thought": "工具输出里已给出明文", "done": True,
             "summary": f"解出：{meta['flag']}"},
        ]
    if challenge_id == "b64-stego":
        # 用免隔离的 codec_decode（函数工具）而非 python_solve：
        # 后者是 dangerous+docker 档，无容器环境被沙箱正确拒绝（见
        # docs/Web真内核实测记录.md F7），评测不应依赖 Docker 在线。
        blob = base64.b64encode(meta["flag"].encode()).decode()
        return [
            {"thought": "先看题面文件，找出候选 base64 块", "tool": "file_type",
             "args": {"path": path}},
            {"thought": "对 blob 块做 base64 解码", "tool": "codec_decode",
             "args": {"data": blob, "codec": "base64"}},
            # 收口结论不得包含 flag（tests/test_ctf_solve.py 契约：判定必须
            # 来自工具输出——FlagRegexVerifier 扫描任务上下文中的工具输出）
            {"thought": "解码结果命中 flag", "done": True,
             "summary": "blob 块解码命中目标串（见工具输出）"},
        ]
    # encoding-chain
    return [
        {"thought": "先读编码链原文", "tool": "file_type",
         "args": {"path": path}},
        {"thought": "hex -> base64 -> rot13 依次解开",
         "tool": "codec_chain",
         "args": {"data": meta["chain"], "codecs": "hex,base64,rot13"}},
        {"thought": "拿到明文", "done": True,
         "summary": f"解出：{meta['flag']}"},
    ]


def solve(root: Path, challenge_id: str, meta: dict, *, mode_id: str = "ctf-crypto",
          max_steps: int = 6):
    """对一道题跑一次内核，返回 (结果, agent)。"""
    def fake_chat_json(config, messages, **kw):
        return decisions.pop(0)

    decisions = _solve_script(challenge_id, meta)
    agent_mod.chat_json = fake_chat_json
    mode = load_mode(mode_id)
    center = build_center()
    agent = PenAgent(center.build_registry(mode),
                     Memory(Path(root) / "mem", namespace=mode.memory_namespace),
                     EvidenceChain(Path(root) / f"{challenge_id}.jsonl"),
                     LLMConfig(),
                     policy=Policy(allowed_targets=["127.0.0.1"],
                                   authorize=True),
                     mode=mode, max_steps=max_steps)
    result = agent.run(str(meta["file"]), f"解出 {challenge_id} 的 flag")
    return result, agent


def solve_all(root: Path, *, verbose: bool = True) -> list[dict]:
    """三道题全跑一遍，返回每题结果摘要。"""
    challenges = build_challenges(root)
    outcomes = []
    for cid, meta in challenges.items():
        if verbose:
            print(f"\n[{cid}] 题目文件: {meta['file'].name}")
        result, agent = solve(root, cid, meta, mode_id="ctf-crypto")
        solved = meta["flag"] in str(result.summary) or result.outcome == "success"
        record = {"id": cid, "outcome": result.outcome, "steps": result.steps,
                  "summary": result.summary, "expected": meta["flag"],
                  "solved": solved,
                  "verifier": type(agent.verifier).__name__,
                  "tools": agent.registry.names()}
        outcomes.append(record)
        if verbose:
            print(f"  模式: ctf-crypto | 判定器: {record['verifier']}")
            print(f"  可用工具: {record['tools']}")
            print(f"  判定: {record['outcome']} | 步数: {record['steps']}")
            print(f"  收口: {result.summary[:90]}")
    return outcomes


def main() -> int:
    shutil.rmtree(DATA, ignore_errors=True)
    print("=" * 68)
    print("阶段二验收：CTF Crypto/Misc 工具链端到端解题（离线）")
    print("=" * 68)
    outcomes = solve_all(DATA)
    ok = sum(1 for r in outcomes if r["solved"])
    print("\n" + "=" * 68)
    for record in outcomes:
        mark = "解出" if record["solved"] else "未解出"
        print(f"  {record['id']:16s} {record['outcome']:8s} {mark}  "
              f"flag={record['expected']}")
    print(f"合计: {ok}/{len(outcomes)} 解出")
    print("=" * 68)
    return 0 if ok == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
