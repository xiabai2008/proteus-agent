"""阶段一验收演示：同一内核 + 同一目标，两种模式跑出不同判定（离线 mock）。

不发起任何真实网络请求：
- LLM 用脚本化决策替代（patch penagent.agent.chat_json）
- 工具是纯函数桩（返回固定 dict，不做 I/O）
- 目标固定 127.0.0.1（默认白名单内）

运行：python examples/eval_mode_switch.py
"""
import shutil
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
from penagent.tools import ToolRegistry, ToolSpec  # noqa: E402

DATA = ROOT / "data" / "eval-mode-switch"
TARGET = "http://127.0.0.1:8080"


def _registry() -> ToolRegistry:
    """工具桩：http_test 属 CTF 白名单；nuclei 被 CTF 模式禁用。"""
    reg = ToolRegistry()
    reg.register(ToolSpec(
        name="http_test", description="HTTP 连通性测试（桩）",
        parameters={"url": {"type": "string"}},
        fn=lambda **kw: {"status": 200, "title": "Demo Portal"}))
    reg.register(ToolSpec(
        name="nuclei", description="模板化漏洞扫描（桩）",
        parameters={"target": {"type": "string"}},
        fn=lambda **kw: {"findings": ["CVE-DEMO-0001"]}))
    return reg


def _agent(mode, decisions, *, max_steps=None, tag=""):
    """构造内核并把 LLM 换成脚本化决策，返回 (agent, result)。"""
    def fake_chat_json(config, messages, **kw):
        return decisions.pop(0)

    agent_mod.chat_json = fake_chat_json
    kwargs = {} if max_steps is None else {"max_steps": max_steps}
    agent = PenAgent(_registry(),
                     Memory(DATA / tag, namespace="demo"),
                     EvidenceChain(DATA / tag / "chain.jsonl"),
                     LLMConfig(),
                     policy=Policy(allowed_targets=["127.0.0.1"],
                                   authorize=True),
                     mode=mode, **kwargs)
    return agent


def _run(agent, objective):
    return agent.run(TARGET, objective)


def section(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def main() -> int:
    shutil.rmtree(DATA, ignore_errors=True)
    pentest = load_mode("pentest-standard")
    ctf = load_mode("ctf-web")

    # ------------------------------------------------------------------
    section("[1] pentest-standard：verifier=evidence_chain")
    agent = _agent(pentest, [
        {"thought": "连通性测试", "tool": "http_test",
         "args": {"url": TARGET}},
        {"thought": "基于证据收口", "done": True,
         "summary": "目标 200 可达，标题 Demo Portal", "evidence_refs": [1]},
    ], tag="pentest")
    print(f"  模式: {pentest.id} | 判定器: {type(agent.verifier).__name__}"
          f" | require_poc={agent.verifier.require_poc}")
    print(f"  步数预算(来自模式 budget.max_steps): {agent.max_steps}"
          f" | 记忆分区: {agent.memory.namespace}")
    print(f"  工具 schema: {[s['name'] for s in agent.registry.schemas()]}")
    r1 = _run(agent, "侦察目标并给出可复现结论")
    print(f"  -> 判定: {r1.outcome} | 步数 {r1.steps}")
    print(f"  -> 结论: {r1.summary}")
    print(f"  -> 证据引用: {r1.evidence_refs}")

    # ------------------------------------------------------------------
    section("[2] ctf-web：verifier=flag_regex（同一内核、同一目标）")
    agent = _agent(ctf, [
        {"thought": "取回页面找 flag", "tool": "http_test",
         "args": {"url": TARGET}},
        {"thought": "拿到 flag", "done": True, "summary": "flag{mode-switch}"},
    ], tag="ctf")
    print(f"  模式: {ctf.id} | 判定器: {type(agent.verifier).__name__}"
          f" | pattern={ctf.verifier.pattern!r} auto_retry={ctf.verifier.auto_retry}")
    print(f"  步数预算(来自模式 budget.max_steps): {agent.max_steps}"
          f" | 记忆分区: {agent.memory.namespace}")
    print(f"  工具 schema: {[s['name'] for s in agent.registry.schemas()]}")
    r2 = _run(agent, "解出本题 flag")
    print(f"  -> 判定: {r2.outcome} | 步数 {r2.steps}")
    print(f"  -> 结论: {r2.summary}")

    print("\n  [2b] 同样收口但结论里没有 flag：CTF 判定器不给过")
    agent = _agent(ctf, [
        {"thought": "收口", "done": True, "summary": "目标 200 可达，未发现 flag"},
    ] * 4, tag="ctf-noflag")
    r2b = _run(agent, "解出本题 flag")
    print(f"  -> 判定: {r2b.outcome} | 步数 {r2b.steps}")
    print(f"  -> 原因: {r2b.summary}")

    # ------------------------------------------------------------------
    section("[3] ctf-web 调用 nuclei：机制性拒绝（非提示词劝退）")
    agent = _agent(ctf, [
        {"thought": "先扫一遍", "tool": "nuclei",
         "args": {"target": TARGET}},
        {"thought": "收口", "done": True, "summary": "flag{denied-tool}"},
    ], tag="ctf-deny")
    print(f"  registry.get('nuclei') -> {agent.registry.get('nuclei')}")
    print(f"  工具 schema 含 nuclei -> "
          f"{'nuclei' in [s['name'] for s in agent.registry.schemas()]}")
    print(f"  提示词含 nuclei -> {'nuclei' in agent._system_prompt([])}")
    r3 = _run(agent, "尝试调用被禁工具")
    mission = agent.memory.get_mission(r3.mission_id)
    blocked = [s for s in mission["steps"] if s.get("blocked")]
    print(f"  -> 拦截原因: {blocked[0]['reason']}")
    levels = [rec.content.get("level") for rec in agent.evidence.load()
              if rec.content.get("blocked")]
    print(f"  -> 留证档位: {levels}")

    # ------------------------------------------------------------------
    section("[4] budget.max_steps 超限：换策略收口，不硬退出")
    decisions = [{"thought": f"试探 {i}", "tool": "http_test",
                  "args": {"url": TARGET}} for i in range(1, 41)]
    decisions.append({"thought": "预算耗尽，收口", "done": True,
                      "summary": "已在预算内完成侦察", "evidence_refs": [1]})
    agent = _agent(pentest, decisions, tag="budget")
    print(f"  模式预算: max_steps={agent.max_steps}（pentest-standard.yaml）")
    print("  脚本化决策: 连续 40 轮调工具，第 41 轮为收口")
    r4 = _run(agent, "侦察（预算耗尽场景）")
    phases = [rec.content.get("phase") for rec in agent.evidence.load()
              if rec.content.get("phase")]
    print(f"  -> 判定: {r4.outcome} | 记录步数 {r4.steps}")
    print(f"  -> 结论: {r4.summary}")
    print(f"  -> 留证阶段标记: {phases}")

    print("\n" + "=" * 68)
    print("演示结束：所有动作均为离线桩，无真实网络请求")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
