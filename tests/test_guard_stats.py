"""守卫与声明统计测试（路线图 P2-2）。

判据落在**可调的三个参数**上（同指纹重复率、p90 步数、假声明率）——守卫参数
此前只能凭感觉调，而它们已经两次直接影响结果：首测那次 60 的总闸门掐断了正在
逼近正确的纠正性调用；重测那次同指纹守卫拦下两条重复调用（拦对了）。

用合成 spool（不依赖仓库 data/，可重复）+ 合成证据链（P2-1 的声明记录）覆盖：
分组与过滤、裁决分布、重复率、步数分位、false-claim 率、人读渲染、CLI 入口。
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from penagent.cli import main                                    # noqa: E402
from penagent.evidence import EvidenceChain                      # noqa: E402
from penagent.guard_stats import (claim_facts, collect, read_spool,  # noqa: E402
                                  render, summarize)


def _spool(tmp_path: Path) -> Path:
    """合成 spool：两个 preset、两条会话、含重复调用与两类裁决记录。"""
    path = tmp_path / "dsh-events.jsonl"
    rows = [
        # 会话 A（proteus-ctf-crypto）：4 次调用，其中 2 次同指纹重复
        {"ts": 1, "session": "sa", "preset": "proteus-ctf-crypto", "kind": "call",
         "tool": "python_solve", "args": "{'code': 'x'}"},
        {"ts": 2, "session": "sa", "preset": "proteus-ctf-crypto", "kind": "result",
         "isError": False, "output": "ok"},
        {"ts": 3, "session": "sa", "preset": "proteus-ctf-crypto", "kind": "call",
         "tool": "python_solve", "args": "{'code': 'x'}"},        # 同指纹
        {"ts": 4, "session": "sa", "preset": "proteus-ctf-crypto", "kind": "result",
         "isError": True, "output": "boom"},
        {"ts": 5, "session": "sa", "preset": "proteus-ctf-crypto", "kind": "call",
         "tool": "native_emu", "args": "{'elf': 'a.so'}"},
        {"ts": 6, "session": "sa", "preset": "proteus-ctf-crypto", "kind": "call",
         "tool": "python_solve", "args": "{'code': 'x'}"},        # 同指纹（第 3 次）
        {"ts": 7, "kind": "supervisor", "session": "sa",
         "tool": "python_solve", "decision": "deny", "repeats": 5, "total": 20},
        # 真实口径：policy 记录带（尽力而为的）preset、不带 session
        {"ts": 8, "kind": "policy", "tool": "pwsh", "decision": "ask",
         "preset": "proteus-ctf-crypto"},
        # 会话 B（standard）：2 次调用 + 一次越界 deny
        {"ts": 9, "session": "sb", "preset": "standard", "kind": "call",
         "tool": "read", "args": "{}"},
        {"ts": 10, "session": "sb", "preset": "standard", "kind": "call",
         "tool": "pwsh", "args": "{'command': 'curl x'}"},
        {"ts": 11, "kind": "policy", "tool": "pwsh", "decision": "deny",
         "preset": "standard"},
        {"ts": 12, "session": "sc", "preset": "proteus-ctf-web", "kind": "call",
         "tool": "http_raw", "args": "{}"},
    ]
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows),
                    encoding="utf-8")
    return path


def test_read_spool_skips_bad_lines(tmp_path):
    path = tmp_path / "s.jsonl"
    path.write_text('{"kind": "call"}\nnot-json\n\n{"kind": "result"}\n',
                    encoding="utf-8")
    records = read_spool(path)
    assert [r["kind"] for r in records] == ["call", "result"]
    assert read_spool(tmp_path / "missing.jsonl") == []


def test_summarize_groups_by_preset_and_counts_decisions(tmp_path):
    stats = summarize(read_spool(_spool(tmp_path)))
    crypto = stats["presets"]["proteus-ctf-crypto"]
    assert crypto["sessions"] == 1
    assert crypto["calls"] == 4
    assert crypto["errors"] == 1
    assert crypto["supervisor"] == {"deny": 1}
    assert crypto["policy"] == {"ask": 1}
    # 同指纹重复：python_solve 那条出现 3 次 → 多出 2 次
    assert crypto["repeats"] == 2
    assert crypto["repeat_rate"] == round(2 / 4, 3)

    default = stats["presets"]["standard"]
    assert default["calls"] == 2 and default["policy"] == {"deny": 1}
    assert default["repeat_rate"] == 0.0


def test_summarize_preset_family_filter(tmp_path):
    records = read_spool(_spool(tmp_path))
    only_proteus = summarize(records, preset="proteus*")
    assert set(only_proteus["presets"]) == {"proteus-ctf-crypto",
                                           "proteus-ctf-web"}
    only_crypto = summarize(records, preset="proteus-ctf-crypto")
    assert set(only_crypto["presets"]) == {"proteus-ctf-crypto"}
    assert summarize(records, preset="standard")["presets"]["standard"]["calls"] == 2


def test_summarize_reports_percentiles(tmp_path):
    stats = summarize(read_spool(_spool(tmp_path)))
    crypto = stats["presets"]["proteus-ctf-crypto"]
    assert (crypto["calls_p50"], crypto["calls_p90"], crypto["calls_max"]) == \
        (4, 4, 4)


def test_claim_facts_and_false_claim_rate(tmp_path):
    """假声明率 = 声称解出但判定器不接受的比例（P2-1 记录 → P2-2 读数）。"""
    data = tmp_path / "data"
    (data / "missions" / "ctf-crypto").mkdir(parents=True)
    (data / "missions" / "ctf-crypto" / "m1.json").write_text(
        json.dumps({"id": "m1"}), encoding="utf-8")
    chain = EvidenceChain(data / "chain.jsonl")
    chain.append("conclusion", {"flag": "flag{a}", "flag_verified": True,
                                "source": "flag_claim", "mission": "m1"})
    chain.append("conclusion", {"flag": "flag{b}", "flag_verified": False,
                                "source": "flag_claim", "mission": "m1"})
    chain.append("conclusion", {"flag": "flag{c}", "flag_verified": False,
                                "source": "flag_claim", "mission": "gone"})
    chain.append("conclusion", {"summary": "普通结论"})       # 不计入

    facts = claim_facts(data)
    assert len(facts) == 3
    stats = summarize([], claims=facts)
    flags = stats["flags"]
    assert flags["claims"] == 3 and flags["verified"] == 1
    assert flags["false_claim_rate"] == round(2 / 3, 3)
    assert flags["by_namespace"]["ctf-crypto"] == {"claims": 2, "verified": 1}
    assert flags["by_namespace"]["(未知)"]["claims"] == 1


def test_collect_and_render_reads_files(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "dsh-events.jsonl").write_text(
        _spool(tmp_path).read_text(encoding="utf-8"), encoding="utf-8")
    stats = collect(data)
    assert stats["records"] == 12
    text = render(stats)
    assert "proteus-ctf-crypto" in text and "重复率" in text
    assert "flag 声明" in text


def test_cli_guards_prints_table(tmp_path, capsys):
    data = tmp_path / "data"
    data.mkdir()
    (data / "dsh-events.jsonl").write_text(
        _spool(tmp_path).read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["guards", "--data", str(data)]) == 0
    out = capsys.readouterr().out
    assert "proteus-ctf-crypto" in out and "守卫统计" in out

    assert main(["guards", "--data", str(data), "--preset", "proteus*",
                 "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload["presets"]) == {"proteus-ctf-crypto", "proteus-ctf-web"}


def test_empty_spool_is_rendered_not_crashed(tmp_path, capsys):
    data = tmp_path / "data"
    data.mkdir()
    assert main(["guards", "--data", str(data)]) == 0
    assert "没有可统计的会话记录" in capsys.readouterr().out
