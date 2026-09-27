"""flag 声明收口（路线图 P2-1，2026-09-27）。

**问题**：宿主直调路径的结论不经内核判定器（R-45）——agent 把 flag 写在聊天或
文件里就走，证据链上只剩"调用过什么"，查不到"它声称的答案是哪个、有没有人
验证过"。P0-1 让 `report_gen` 能**事后**读出"报告里的 flag 有没有判定器背书"，
但声明本身仍是隐形的。

**这个工具把声明变成一条可查的记录**：调用时
1. 抽查 flag 形态（与模式默认正则同形）；
2. 当场核对证据链里有没有判定器（`native_emu`）接受过它；
3. 无论 verified / unverified 都写一条 `conclusion` 记录并入作战记录
   （`flag_claims`）——**未验证只标注，不判失败**（P0-1 拍板语义）。

消费端：评分卡据此算**假声明率**（声称解出但判定器不接受的比例）——
这是本轮实测里最致命的失败模式（首测交的 flag 过不了题目自己的 checker）。
"""
from __future__ import annotations

import re
from pathlib import Path

from penagent.evidence import EvidenceChain
from penagent.memory import Memory
from penagent.verifier import ORACLE_TOOLS, oracle_accepts

#: flag 形态（与 CTF 模式默认判定正则同形；模式自定义 pattern 更宽/更严都行，
#: 这里只挡"根本不是 flag"的输入）
_FLAG_SHAPE = re.compile(r"(?i)^(flag|ctf)\{[^}]{1,200}\}$")


def flag_claim(flag: str = "", mission_id: str = "", note: str = "",
               data_dir: str = "") -> dict:
    """记录一次 flag 声明并核对判定器接受性（verified / unverified）。

    - `flag`：要声明的 flag（原样，不要在工具里改写大小写或括号）；
    - `mission_id`：缺省由内核层填会话绑定任务（宿主直调）；CLI 路径由主循环填；
      仍为空时按**全链**核对，并在返回里标注这一点；
    - `note`：可选说明（例如"题目没有 checker，用 XX 方式等价验证"）。

    返回 `verified` 是核对的结论：True = 证据链里有判定器接受过这个 flag；
    False = 没有——**不代表 flag 是错的**，只代表未经验证，请补跑判定器或
    在 note 里写清等价验证方式。
    """
    from penagent.http_session import DATA_DIR as _DEFAULT_DATA_DIR

    text = str(flag or "").strip()
    if not text:
        return {"ok": False, "error": "缺少 flag 参数",
                "hint": "把要声明的 flag 原样传进来（如 flag{...}）"}
    if not _FLAG_SHAPE.match(text):
        return {"ok": False, "error": f"{text[:80]!r} 不是 flag 形态"
                                      f"（形如 flag{{...}} / ctf{{...}}）",
                "hint": "确认拿到的字符串完整（含大括号），不要在工具里改写"}
    mid = str(mission_id or "").strip()
    data = Path(data_dir or _DEFAULT_DATA_DIR)
    chain = EvidenceChain(data / "chain.jsonl")
    verified = oracle_accepts(text, chain, mission=mid)
    reason = (
        f"判定器（{'/'.join(ORACLE_TOOLS)}）已接受该 flag"
        if verified else
        f"证据链里没有判定器（{'/'.join(ORACLE_TOOLS)}）接受该 flag 的记录"
        f"——按未验证标注（不判失败）"
    )
    if not mid:
        reason += "；本次未绑定任务，按全链核对"
    record = chain.append("conclusion", {
        "flag": text,
        "flag_verified": verified,
        "source": "flag_claim",
        "verdict": (f"flag 声明（claim）：{text}"
                    f"（{'已接受' if verified else '未验证'}）"),
        **({"mission": mid} if mid else {}),
        **({"note": str(note)} if note else {}),
    })
    result: dict = {"ok": True, "flag": text, "verified": verified,
                    "reason": reason, "record_seq": record.seq}
    if mid:
        result["mission"] = mid
        # 作战记录（跨分区找任务；找不到只标注，不影响工具语义）
        try:
            namespace = Memory.note_flag_claim_anywhere(data, mid, text,
                                                        verified)
        except Exception:            # noqa: BLE001 —— 记录失败不改工具语义
            namespace = None
        if namespace:
            result["mission_namespace"] = namespace
        else:
            result["mission_note"] = "任务记录未找到（声明只落在证据链上）"
    if not verified:
        result["hint"] = ("先跑判定器：题目自带 checker 时用 native_emu "
                          "（str:flag{...},len,...）拿到 accept 再声明；"
                          "题目没有 checker 时在 note 里写清你的等价验证方式，"
                          "并在结论里如实标注未验证")
    return result
