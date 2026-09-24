"""审计层级视图测试（P2-3）。

覆盖三层关系与两条边界：
- **Task → Action → Artifact**：任务从作战记录取，动作走步骤里的
  `evidence_seq`，产出从链记录取（含"是否被结论引用"）
- **归属前提**：链记录必须带 `mission`/`step`（`_append_evidence` 写入）
- **边界一：老链兜底**——记录没有 `mission` 字段时按 (mission, step) 配对
- **边界二：不静默丢**——无归属记录单独列在 `unlinked` 里
"""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from penagent.agent import PenAgent, Policy  # noqa: E402
from penagent.cli import main as cli_main  # noqa: E402
from penagent.evidence import EvidenceChain  # noqa: E402
from penagent.llm import LLMConfig  # noqa: E402
from penagent.memory import Memory  # noqa: E402
from penagent.modes import load_mode  # noqa: E402
from penagent.registry import build_center  # noqa: E402
from penagent.report import mission_tree, render_tree  # noqa: E402


def _run_agent(tmp_path, decisions, *, mode_id="ctf-crypto", max_steps=5):
    """跑一个脚本化任务，返回 (result, agent, data_dir)。"""
    data = tmp_path / "tree-data"
    data.mkdir(parents=True, exist_ok=True)
    import penagent.agent as agent_mod

    queue = list(decisions)
    agent_mod.chat_json = lambda config, messages, **kw: queue.pop(0)
    mode = load_mode(mode_id)
    center = build_center()
    agent = PenAgent(center.build_registry(mode),
                     Memory(data, namespace=mode.memory_namespace),
                     EvidenceChain(data / "chain.jsonl"), LLMConfig(),
                     policy=Policy(allowed_targets=["127.0.0.1"],
                                   authorize=True),
                     mode=mode, max_steps=max_steps)
    result = agent.run("127.0.0.1", "层级视图测试任务")
    return result, agent, data


DECISIONS = [
    {"thought": "先解码", "tool": "codec_decode",
     "args": {"data": "ZmxhZ3t0cmVlX29rX2FiY30=", "codec": "base64"}},
    {"thought": "解出来了", "done": True,
     "summary": "解出：flag{tree_ok_abc}", "evidence_refs": [2]},
]


def test_records_carry_mission_and_step(tmp_path):
    """归属前提：链记录必须带 mission/step，作战记录步骤要带 evidence_seq。"""
    _result, agent, data = _run_agent(tmp_path, DECISIONS)
    calls = [r for r in agent.evidence.load() if r.kind == "tool_call"]
    assert calls, "应有工具调用记录"
    assert all(r.content.get("mission") for r in calls), \
        "链记录缺 mission —— 层级视图会退化成按 seq 猜"
    assert all("step" in r.content for r in calls)
    assert all("evidence_seq" in s for s in
               agent.memory.list_missions()[0]["steps"])


def test_tree_links_task_action_and_artifact(tmp_path):
    result, _agent, data = _run_agent(tmp_path, DECISIONS)
    tree = mission_tree(str(data))

    assert tree["chain_ok"] is True
    assert len(tree["tasks"]) == 1
    task = tree["tasks"][0]
    assert task["id"] == result.mission_id
    assert task["outcome"] == "success"
    assert task["evidence_refs"], "结论应引用证据"

    action = task["actions"][0]
    assert action["tool"] == "codec_decode" and action["ok"] is True
    assert action["evidence_seq"] is not None
    artifact = action["artifacts"][0]
    assert artifact["seq"] == action["evidence_seq"]
    assert artifact["chars"] > 0 and len(artifact["digest"]) == 12
    assert artifact["cited"] is True          # 被结论引用（evidence_refs=[2]）
    assert task["conclusions"] and \
        task["conclusions"][0]["summary"].startswith("解出")


def test_legacy_chain_without_mission_falls_back_to_step_pairing(tmp_path):
    """老链兜底：记录没带 mission 时，按 (mission, step) 配对仍然成树。"""
    _result, agent, data = _run_agent(tmp_path, DECISIONS)
    # 把链上的 mission 字段抹掉，模拟 P2-3 之前的链
    path = data / "chain.jsonl"
    rows = [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in rows:
        row["content"].pop("mission", None)
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows),
                    encoding="utf-8")

    tree = mission_tree(str(data))
    assert tree["tasks"][0]["actions"][0]["evidence_seq"] is not None
    assert tree["tasks"][0]["actions"][0]["artifacts"][0]["cited"] is True


def test_unlinked_records_are_listed_not_dropped(tmp_path):
    """无归属记录不静默丢：单独列出来（与审计桥"归属未知不过滤"同源）。"""
    _result, _agent, data = _run_agent(tmp_path, DECISIONS)
    chain = EvidenceChain(data / "chain.jsonl")
    chain.append("tool_call", {"tool": "pwsh", "ok": True,
                               "output": "host-side action"})

    tree = mission_tree(str(data))
    assert [u["seq"] for u in tree["unlinked"]] == [tree["chain_length"]]
    text = render_tree(tree)
    assert "未归属记录 1 条" in text


NO_REF_DECISIONS = [
    {"thought": "结论直接给出 flag", "done": True,
     "summary": "解出：flag{tree_no_ref}"},
]


def test_flag_verdict_empty_refs_is_annotated(tmp_path):
    """flag 判定不要求结论引用证据：空引用要注明，别读成"没有证据"（R-42）。"""
    _result, _agent, data = _run_agent(tmp_path, NO_REF_DECISIONS)

    task = mission_tree(str(data))["tasks"][0]
    assert task["outcome"] == "success"
    assert task["flag_judged"] is True      # 由 flag 判定收口
    assert task["evidence_refs"] == []      # 无引用是正常形态，不是缺证据

    text = render_tree(mission_tree(str(data)))
    assert "证据引用 （无——flag 判定不要求引用）" in text


def test_cli_tree_renders_and_emits_json(tmp_path, capsys):
    result, _agent, data = _run_agent(tmp_path, DECISIONS)

    assert cli_main(["tree", "--data", str(data)]) == 0
    out = capsys.readouterr().out
    assert f"任务 {result.mission_id}" in out
    assert "├─ #1 codec_decode" in out and "被结论引用" in out
    assert "└─ 结论" in out

    assert cli_main(["tree", "--data", str(data), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tasks"][0]["actions"][0]["artifacts"][0]["cited"] is True


def test_tree_unknown_mission_is_empty_not_error(tmp_path, capsys):
    _result, _agent, data = _run_agent(tmp_path, DECISIONS)
    assert cli_main(["tree", "--data", str(data), "--mission", "nope"]) == 0
    assert "没有作战记录" in capsys.readouterr().out
