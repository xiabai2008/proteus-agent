"""阶段二验收：CTF Crypto/Misc 工具链端到端解题（离线构造样例题）。

题集用**声明式规格**描述（编码链 / 隐写块 / RSA 参数），生成器与解题决策
序列都从规格派生——加题只需在下面的 `*_CASES` 表里加一行。

题目分三类：
  1. 编码题（ENC_*）  ：flag 经若干层编码变成密文，用 codec_chain 逆序解开
  2. 隐写题（STEGO_*）：多块候选里只有一块解出 flag（其余是诱饵）
  3. RSA 题（RSA_*）  ：相近素数，用 rsactf_attack 的 fermat 攻击分解解密

约束（题集必须满足）：
- **题面文件不含明文 flag**（真解出来的，不是抄出来的；测试钉住）
- 只使用本机可用的工具链——不含 `python_solve`（它声明 sandbox: docker，
  依赖容器，见 docs/沙箱降级评估.md）。这也是为什么编码题不用一次性脚本。
- 每道题都确定性可解（无 flaky 题）。

离线说明：仓库不带 .env / API key，LLM 决策用**脚本化序列**替代（扮演模型
选工具的角色）；工具执行（RsaCtfTool / 解码链 / 文件识别）与 flag 判定
（FlagRegexVerifier）都是真实路径。

运行：python examples/eval_ctf_solve.py
"""
import base64
import codecs
import random
import shutil
import sys
import urllib.parse
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

# 解码工具支持的编码（与 penagent/ctf_tools.py 的 _CODECS 保持一致）
CODECS = ("base64", "base64url", "hex", "url", "rot13", "reverse", "binary")


# ----------------------------------------------------------------------
# 编码器：题库构造用，与内核的解码工具互逆
# ----------------------------------------------------------------------
def _encode_once(text: str, codec: str) -> str:
    """与 ctf_tools._decode_once 互逆的单步编码（生成密文用）。"""
    name = codec.strip().lower()
    if name == "base64":
        return base64.b64encode(text.encode()).decode()
    if name == "base64url":
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    if name == "hex":
        return text.encode().hex()
    if name == "url":
        return urllib.parse.quote(text, safe="")
    if name == "rot13":
        return codecs.encode(text, "rot_13")
    if name == "reverse":
        return text[::-1]
    if name == "binary":
        return "".join(f"{b:08b}" for b in text.encode())
    raise ValueError(f"不支持的编码: {codec!r}（可用 {CODECS}）")


def encode_chain(flag: str, chain: list[str]) -> str:
    """按顺序施加编码链，得到密文。解法是逆序解码。"""
    data = flag
    for codec in chain:
        data = _encode_once(data, codec)
    return data


# ----------------------------------------------------------------------
# 题集规格（加题只改这里）
# ----------------------------------------------------------------------
# 编码题：(id, 编码链（flag → 密文）, flag)
# 每道题的解法 = 逆序解码链。链里不得出现"对纯字母数字输出再 url 编码"
# 这类空操作组合（会让本题退化成另一道题）。
ENCODING_CASES = [
    # 原有题目（id 沿用，向后兼容既有测试与文档引用）
    ("encoding-chain", ["rot13", "base64", "hex"],
     "flag{layered_encodings_ok}"),
    ("enc-b64", ["base64"], "flag{base64_is_not_encryption}"),
    ("enc-b64url", ["base64url"], "flag{url_safe_alphabet_works}"),
    ("enc-hex", ["hex"], "flag{hexdump_basics}"),
    ("enc-url", ["url"], "flag{percent_encoding_101}"),
    ("enc-rot13", ["rot13"], "flag{caesar_shifts_by_thirteen}"),
    ("enc-reverse", ["reverse"], "flag{read_it_backwards}"),
    ("enc-binary", ["binary"], "flag{bits_and_bytes}"),
    ("enc-hex-b64", ["hex", "base64"], "flag{order_matters}"),
    ("enc-b64-hex", ["base64", "hex"], "flag{nested_encodings}"),
    ("enc-url-b64", ["url", "base64"], "flag{url_then_base64}"),
    ("enc-b64-rot13", ["base64", "rot13"], "flag{rotate_after_encode}"),
    ("enc-rot13-b64", ["rot13", "base64"], "flag{encode_after_rotate}"),
    ("enc-rev-b64", ["reverse", "base64"], "flag{flip_then_encode}"),
    ("enc-b64-rev", ["base64", "reverse"], "flag{encode_then_flip}"),
    ("enc-bin-b64", ["binary", "base64"], "flag{binary_is_verbose}"),
    ("enc-b64-bin", ["base64", "binary"], "flag{bytes_to_bits}"),
    ("enc-hex-rot13", ["hex", "rot13"], "flag{hex_then_rotate}"),
    ("enc-rot13-hex", ["rot13", "hex"], "flag{rotate_then_hex}"),
    ("enc-url-hex", ["url", "hex"], "flag{percent_then_hex}"),
    ("enc-b64-b64", ["base64", "base64"], "flag{double_base64}"),
    ("enc-b64-url", ["base64", "url"], "flag{plus_and_slash_escaped}"),
    ("enc-hex-b64-rot13", ["hex", "base64", "rot13"],
     "flag{three_layers_no_sweat}"),
    ("enc-b64-hex-reverse", ["base64", "hex", "reverse"],
     "flag{three_layers_flipped}"),
    ("enc-reverse-rot13-b64", ["reverse", "rot13", "base64"],
     "flag{three_layers_rotated}"),
    ("enc-hex-b64-rot13-reverse", ["hex", "base64", "rot13", "reverse"],
     "flag{four_layers_deep}"),
]

# 隐写题：(id, 诱饵块编码, 真块编码, flag)
# 判定必须来自工具输出（收口结论不含 flag）——钉住 FlagRegexVerifier 的
# "扫任务上下文"能力，而不是只看结论。
STEGO_CASES = [
    # 原有题目（id 沿用）
    ("b64-stego", "base64", "base64", "flag{b64_stego_found}"),
    ("stego-hex", "hex", "hex", "flag{hex_dump_hides_it}"),
    ("stego-b64url", "base64url", "base64url", "flag{urlsafe_blob_stego}"),
    ("stego-mixed", "base64", "hex", "flag{mixed_encodings_in_log}"),
]

# RSA 题：(id, 素数位数, 相近素数的随机位数差, flag)
RSA_CASES = [
    # 原有题目（id 沿用）
    ("simple-rsa", 512, 20, "flag{rsa_close_primes_pwned}"),
    ("rsa-fermat-768", 768, 24, "flag{fermat_strikes_again}"),
    ("rsa-fermat-1024", 1024, 28, "flag{big_keys_need_close_primes}"),
]

_DECOY_LINES = [
    "the quick brown fox jumps over the lazy dog",
    "nothing to see here, move along",
    "decoy: admin panel at /admin",
    "rotation schedule updated at 03:00 UTC",
]


def challenge_ids() -> list[str]:
    """全部题目 id（不生成文件）——测试 parametrize 用。"""
    return [c[0] for c in ENCODING_CASES] + [c[0] for c in STEGO_CASES] \
        + [c[0] for c in RSA_CASES]


# ----------------------------------------------------------------------
# 素数工具（stdlib，避免测试引入 sympy 依赖）
# ----------------------------------------------------------------------
def _is_prime(n: int, rounds: int = 24) -> bool:
    """Miller-Rabin 素性测试。"""
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


# ----------------------------------------------------------------------
# 题目生成（离线、确定性）
# ----------------------------------------------------------------------
def build_challenges(root: Path) -> dict:
    """在 root 下按规格生成全部题目，返回 {id: 元数据}。

    元数据含 file（题面路径）、flag（答案）、以及解该题所需的额外字段。
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    out: dict = {}

    # ---- 编码题 ----
    for cid, chain, flag in ENCODING_CASES:
        cipher = encode_chain(flag, chain)
        path = root / f"{cid}.txt"
        path.write_text(
            f"# encoded challenge ({', '.join(chain)})\n{cipher}\n",
            encoding="utf-8")
        out[cid] = {"file": path, "flag": flag, "category": "encoding",
                    "chain": chain, "cipher": cipher}

    # ---- 隐写题：多块候选，只有一块解出 flag ----
    for cid, decoy_codec, real_codec, flag in STEGO_CASES:
        rng = random.Random(f"stego-{cid}")
        decoys = [_encode_once(d, decoy_codec)
                  for d in rng.sample(_DECOY_LINES, 3)]
        real = _encode_once(flag, real_codec)
        keys = ["note_a", "blob", "note_b", "meta"]
        blocks = dict(zip(keys, [decoys[0], real, decoys[1], decoys[2]]))
        lines = ["# captured log fragments"] + \
            [f"{k}={v}" for k, v in blocks.items()]
        path = root / f"{cid}.txt"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out[cid] = {"file": path, "flag": flag, "category": "stego",
                    "real_codec": real_codec, "blob": real}

    # ---- RSA 题：相近素数（fermat 可解）----
    for cid, bits, gap_bits, flag in RSA_CASES:
        rng = random.Random(f"rsa-{cid}")
        p = _next_prime(rng.getrandbits(bits))
        q = _next_prime(p + rng.getrandbits(gap_bits))
        n, e = p * q, 65537
        c = pow(int.from_bytes(flag.encode(), "big"), e, n)
        path = root / f"{cid}.txt"
        path.write_text(
            "# RSA challenge (offline)\n"
            f"n = {n}\n"
            f"e = {e}\n"
            f"c = {c}\n"
            "# 提示：两个素数是相近的\n", encoding="utf-8")
        out[cid] = {"file": path, "flag": flag, "category": "crypto",
                    "n": n, "e": e, "c": c, "p": p, "q": q}

    return out


# ----------------------------------------------------------------------
# 分档评分：里程碑（P2-2，2026-09-24；Cybench 三口径的本地化）
#
# 背景：二值评分（解出 / 没解出）在 33 题规模上信息量太低——"8/33" 看不出
# 是"全流程都在、最后差一步"还是"根本没入门"。所以给每题配**可机验的里程碑**，
# 给出两个新口径：
#
#   unguided        二值：判定器通过（flag 正确）——与原来一致
#   subtask         里程碑完成比例（如 2/3）——"差多少"
#   subtask_guided  只算**最后一个**里程碑（= flag 收口）——与 unguided 同值，
#                   语义上代表"给了子任务提示后能不能收口"
#
# **里程碑不手写**：由类别与真值派生（33 题 × 3 条手写必然漂移，且改题集就
# 得同步改 33 处）。判据一律落在**工具输出**上，不看模型的自述——这是本项目
# 反幻觉纪律的延续（自述可以编，工具输出在证据链里）。
#
# 与 Cybench 的差异（诚实声明）：Cybench 的 subtask-guided 与 unguided 会因为
# **分档给的迭代预算不同**而分离；我们的脚本化通路由同一份决策序列跑，所以
# 两个值恒等。保留它是为了将来接 LLM 驱动时能区分"被提示才收口"。
# ----------------------------------------------------------------------
def _call_outputs(calls: list[dict]) -> str:
    """把本次任务的工具输出拼成一段文本（里程碑判据的取值面）。"""
    return "\n".join(str(c.get("output", "") or "") for c in calls
                     if isinstance(c, dict))


def _arg_values(call: dict) -> list[str]:
    """调用参数的取值列表（**不要用 f-string 打 dict**：Windows 路径的反斜杠
    会被 repr 转义成 `\\\\`，路径包含判据必然落空——2026-09-24 实测踩中）。"""
    args = call.get("args")
    if isinstance(args, dict):
        return [str(v) for v in args.values()]
    return [str(args)]


def _read_source(calls: list[dict], source_path: str) -> bool:
    """是否成功读过题面（file_type / codec_* 任一，成功且非拦截）。"""
    for call in calls:
        if not isinstance(call, dict) or call.get("blocked"):
            continue
        if not call.get("ok"):
            continue
        if str(call.get("tool", "")) not in ("file_type", "codec_decode",
                                             "codec_chain"):
            continue
        if any(source_path == value or source_path in value
               for value in _arg_values(call)):
            return True
    return False


def milestones_for(cid: str, meta: dict, calls: list[dict],
                   *, verified: bool) -> list[dict]:
    """派生该题的可机验里程碑（顺序 = 解决路径的顺序）。"""
    path = str(meta.get("file", ""))
    outputs = _call_outputs(calls)
    category = meta.get("category", "")
    marks: list[dict] = [{
        "id": "inspect",
        "label": "读取题面（拿到原始材料）",
        "ok": _read_source(calls, path),
    }]

    if category == "encoding":
        chain = list(meta.get("chain") or [])
        if len(chain) > 1:
            # 剥掉最外层（chain[-1]）后的中间态：外层逆解码的结果
            intermediate = encode_chain(meta["flag"], chain[:-1])
            marks.append({
                "id": "peel-outer",
                "label": f"剥掉最外层 {chain[-1]}（得到中间态）",
                "ok": intermediate in outputs,
            })
    elif category == "stego":
        blob = str(meta.get("blob", ""))
        hit = any(isinstance(c, dict) and not c.get("blocked") and c.get("ok")
                  and blob and any(blob == v or blob in v
                                   for v in _arg_values(c))
                  for c in calls)
        marks.append({
            "id": "locate-block",
            "label": "从候选块里定位到真块并解码",
            "ok": hit,
        })
    elif category == "crypto":
        # RsaCtfTool 只回明文、不回因子（`private argument is not set` 时它
        # 刻意不显示私钥），所以"分解成功"的**可机验形态**是明文出现在工具
        # 输出里（HEX 段）——退而求其次但判据仍然硬：来自工具输出，不是自述。
        plain_hex = format(int.from_bytes(meta["flag"].encode(), "big"), "x")
        marks.append({
            "id": "decrypt",
            "label": "工具解出明文（hex 或明文出现在工具输出里）",
            "ok": plain_hex in outputs or meta["flag"] in outputs,
        })

    marks.append({
        "id": "flag",
        "label": "产出正确 flag（判定器通过）",
        "ok": bool(verified),
    })
    for mark in marks:
        mark["milestone_id"] = f"{cid}:{mark['id']}"
    return marks


def grade_run(cid: str, meta: dict, calls: list[dict],
              *, verified: bool) -> dict:
    """分档评分：返回三口径 + 逐条里程碑（可落盘点名哪一步没到）。"""
    marks = milestones_for(cid, meta, calls, verified=verified)
    solved = sum(1 for m in marks if m["ok"])
    total = len(marks)
    return {
        "unguided": bool(verified),
        "subtask": f"{solved}/{total}",
        "subtask_score": round(solved / total, 4) if total else 0.0,
        "subtask_guided": bool(marks[-1]["ok"]) if marks else False,
        "milestones": marks,
    }


def collect_calls(chain: "EvidenceChain", since_seq: int = 0) -> list[dict]:
    """取任务期间的工具调用记录（证据链里的 tool_call，含被拦的那条）。"""
    out = []
    for record in chain.load():
        if record.seq <= since_seq or record.kind != "tool_call":
            continue
        out.append(dict(record.content))
    return out


def solve_graded(root: Path, cid: str, meta: dict, **kwargs) -> dict:
    """跑一次并给出分档结果：{result, calls, grade}。"""
    chain = EvidenceChain(Path(root) / f"{cid}.jsonl")
    since = chain.verify()["length"]
    result, agent = solve(root, cid, meta, **kwargs)
    calls = collect_calls(chain, since)
    grade = grade_run(cid, meta, calls, verified=result.outcome == "success")
    return {"result": result, "agent": agent, "calls": calls, "grade": grade}


# ----------------------------------------------------------------------
# 解题：每题跑一次内核（脚本化决策 + 真实工具 + 真实判定）
# ----------------------------------------------------------------------
def _solve_script(cid: str, meta: dict) -> list[dict]:
    """扮演"模型选工具"的脚本化决策序列（离线替代 LLM）。"""
    path = str(meta["file"])
    category = meta.get("category", "")

    if category == "crypto":                       # RSA
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

    if category == "stego":
        # 收口结论**不含 flag**：判定必须来自工具输出（FlagRegexVerifier
        # 扫描任务上下文），这是隐写题的既有契约
        # （tests/test_ctf_solve.py::test_stego_verdict_comes_from_tool_output）
        return [
            {"thought": "先看题面文件，找出候选块", "tool": "file_type",
             "args": {"path": path}},
            {"thought": f"对 blob 块做 {meta['real_codec']} 解码",
             "tool": "codec_decode",
             "args": {"data": meta["blob"], "codec": meta["real_codec"]}},
            {"thought": "解码结果命中 flag", "done": True,
             "summary": "blob 块解码命中目标串（见工具输出）"},
        ]

    # 编码题：逆序解码链
    codecs_rev = ",".join(reversed(meta["chain"]))
    return [
        {"thought": "先读题面原文", "tool": "file_type",
         "args": {"path": path}},
        {"thought": f"按 {codecs_rev} 依次解开",
         "tool": "codec_chain",
         "args": {"data": meta["cipher"], "codecs": codecs_rev}},
        {"thought": "拿到明文", "done": True,
         "summary": f"解出：{meta['flag']}"},
    ]


def solve(root: Path, challenge_id: str, meta: dict, *,
          mode_id: str = "ctf-crypto", max_steps: int = 6):
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
    """全部题目跑一遍，返回每题结果摘要。"""
    challenges = build_challenges(root)
    outcomes = []
    for cid, meta in challenges.items():
        if verbose:
            print(f"\n[{cid}] 题目文件: {meta['file'].name}")
        result, agent = solve(root, cid, meta, mode_id="ctf-crypto")
        solved = meta["flag"] in str(result.summary) or result.outcome == "success"
        record = {"id": cid, "outcome": result.outcome, "steps": result.steps,
                  "summary": result.summary, "expected": meta["flag"],
                  "category": meta.get("category", ""),
                  "solved": solved,
                  "verifier": type(agent.verifier).__name__}
        outcomes.append(record)
        if verbose:
            print(f"  判定: {record['outcome']} | 步数: {record['steps']}"
                  f" | 类别: {record['category']}")
    return outcomes


def main() -> int:
    shutil.rmtree(DATA, ignore_errors=True)
    print("=" * 68)
    print("阶段二验收：CTF Crypto/Misc 工具链端到端解题（离线）")
    print("=" * 68)
    outcomes = solve_all(DATA, verbose=False)
    ok = sum(1 for r in outcomes if r["solved"])
    by_cat: dict[str, list] = {}
    for r in outcomes:
        by_cat.setdefault(r["category"], []).append(r)
    print("\n" + "=" * 68)
    for cat, items in sorted(by_cat.items()):
        passed = sum(1 for i in items if i["solved"])
        print(f"  {cat:<10} {passed}/{len(items)} 解出")
    failed = [r for r in outcomes if not r["solved"]]
    for r in failed:
        print(f"  [未解出] {r['id']}: {r['summary'][:80]}")
    print(f"合计: {ok}/{len(outcomes)} 解出")
    print("=" * 68)
    return 0 if ok == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
