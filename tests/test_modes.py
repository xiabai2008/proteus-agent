"""模式档案测试：加载 / inherits 深合并 / 校验失败 / 能力过滤机制性生效。"""
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.agent import PenAgent
from penagent.evidence import EvidenceChain
from penagent.llm import LLMConfig
from penagent.memory import Memory
from penagent.modes import ModeError, load_mode, load_modes
from penagent.tools import ToolRegistry, ToolSpec

PROMPT_STUB = "模式提示词\n工具:\n{tools}\n技能:\n{skills}\n"


def _write_mode(tmp_path: Path, name: str, body: str) -> Path:
    """在临时目录写一个模式文件，并准备好它引用的提示词模板。"""
    modes_dir = tmp_path / "modes"
    modes_dir.mkdir(exist_ok=True)
    (modes_dir / f"{name}.yaml").write_text(body, encoding="utf-8")
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir(exist_ok=True)
    (prompts_dir / "stub.md").write_text(PROMPT_STUB, encoding="utf-8")
    return modes_dir


def _registry(*names: str) -> ToolRegistry:
    reg = ToolRegistry()
    for name in names:
        reg.register(ToolSpec(name=name, description=f"{name} 工具",
                              parameters={"host": {"type": "string"}}))
    return reg


def _agent(tmp_path: Path, mode=None, *tools: str) -> PenAgent:
    return PenAgent(_registry(*(tools or ("port_scan", "http_probe"))),
                    Memory(tmp_path / "mem"),
                    EvidenceChain(tmp_path / "chain.jsonl"),
                    LLMConfig(), mode=mode)


# ----------------------------------------------------------------------
# 1. 模式加载
# ----------------------------------------------------------------------
def test_load_modes_from_repo_directory():
    modes = load_modes()
    assert set(modes) == {"base", "pentest-standard", "ctf-web", "ctf-crypto"}

    pentest = modes["pentest-standard"]
    assert pentest.label == "常规渗透测试模式"
    assert pentest.memory_namespace == "pentest-standard"
    assert pentest.sandbox == "docker"
    assert pentest.capability.constraint_for("nuclei") == \
        "-severity low,medium,high -c 25"
    assert pentest.permission.level_for("httpx") == "ok"
    assert pentest.permission.level_for("sqlmap") == "ask"
    assert pentest.permission.level_for("mimikatz") == "deny"
    assert pentest.verifier.type == "evidence_chain"
    assert pentest.verifier.require_poc is True

    ctf = modes["ctf-web"]
    assert ctf.verifier.type == "flag_regex"
    assert ctf.verifier.auto_retry == 3
    assert ctf.verifier.compiled_pattern().search("x CTF{abc} y")
    assert ctf.read_system_prompt().startswith("你是 XPentest")
    # 模式文件按 id 可单独加载，且与批量加载结果一致
    assert load_mode("ctf-web").verifier.pattern == ctf.verifier.pattern


def test_profile_is_immutable_at_runtime():
    mode = load_mode("ctf-web")
    with pytest.raises(FrozenInstanceError):
        mode.sandbox = "none"
    with pytest.raises(TypeError):
        mode.capability.constraints["nuclei"] = "-x"


# ----------------------------------------------------------------------
# 2. inherits 深合并（子覆盖父 + 未声明字段继承）
# ----------------------------------------------------------------------
def test_inherits_deep_merge():
    ctf = load_mode("ctf-web")

    # 覆盖：列表整体替换（不拼接），标量覆盖
    assert ctf.budget.max_steps == 60                     # base 40 -> 60
    assert ctf.scope.network_egress is True               # base False -> True
    assert set(ctf.capability.deny) == {"nuclei", "fscan", "sqlmap"}
    assert ctf.skills == ("ctf-web",)
    assert ctf.inherits == "base"

    # 继承：子文件未声明的字段来自 base（嵌套映射逐键合并）
    assert ctf.scope.requires_explicit_allowlist is True  # base 的 required
    assert ctf.budget.model_tier["reason"] == "strong"    # base 的 model_tier
    assert ctf.permission.default == "ask"                # base 的默认档位
    # sandbox 被 CTF 模式显式覆盖为 docker：解题脚本等价宿主任意代码执行，
    # 容器不可用时该工具被拒绝，绝不回落裸跑（见 ctf-web.yaml）
    assert ctf.sandbox == "docker"
    assert load_mode("pentest-standard").sandbox == "docker"
    # base 刻意不声明 require_poc，故不会随深合并泄漏进 CTF 模式
    assert ctf.verifier.require_poc is False


def test_inherits_missing_parent_rejected(tmp_path):
    modes_dir = _write_mode(tmp_path, "orphan", (
        "id: orphan\n"
        "inherits: not-exist\n"
        "persona: {system_prompt: prompts/stub.md}\n"
        "budget: {max_steps: 5}\n"
        "verifier: {type: evidence_chain}\n"))
    with pytest.raises(ModeError, match="inherits 目标不存在"):
        load_mode("orphan", modes_dir=modes_dir)


def test_inherits_cycle_rejected(tmp_path):
    modes_dir = _write_mode(tmp_path, "a", (
        "id: a\ninherits: b\n"
        "persona: {system_prompt: prompts/stub.md}\n"
        "budget: {max_steps: 5}\nverifier: {type: evidence_chain}\n"))
    (modes_dir / "b.yaml").write_text((
        "id: b\ninherits: a\n"
        "persona: {system_prompt: prompts/stub.md}\n"
        "budget: {max_steps: 5}\nverifier: {type: evidence_chain}\n"),
        encoding="utf-8")
    with pytest.raises(ModeError, match="成环"):
        load_mode("a", modes_dir=modes_dir)


# ----------------------------------------------------------------------
# 3. 字段校验失败
# ----------------------------------------------------------------------
def _body(**override) -> str:
    """基线模式定义，按段覆盖（避免 YAML 重复键带来的歧义）。"""
    sections = {
        "persona": "persona: {system_prompt: prompts/stub.md}\n",
        "capability": "",
        "permission": "",
        "budget": "budget: {max_steps: 5}\n",
        "scope": "",
        "verifier": "verifier: {type: evidence_chain}\n",
    }
    sections.update(override)
    return "id: bad\n" + "".join(sections.values())


@pytest.mark.parametrize("override, message", [
    ({"permission": "permission: {default: maybe}\n"}, "permission.default"),
    ({"capabilty": "capabilty: {allow: ['*']}\n"}, "未知顶层字段"),
    ({"capability": "capability: {allow: ['*'], deni: []}\n"}, "未知字段"),
    ({"verifier": "verifier: {type: flag_regex}\n"}, "必须提供 pattern"),
    ({"verifier": "verifier: {type: flag_regex, pattern: '(?i)(flag{'}\n"},
     "非法正则"),
    ({"budget": "budget: {max_steps: 0}\n"}, "正整数"),
    ({"scope": "scope: {network_egress: \"yes\"}\n"}, "布尔值"),
    ({"persona": "persona: {system_prompt: prompts/missing.md}\n"},
     "文件不存在"),
])
def test_invalid_mode_rejected(tmp_path, override, message):
    modes_dir = _write_mode(tmp_path, "bad", _body(**override))
    with pytest.raises(ModeError, match=message):
        load_mode("bad", modes_dir=modes_dir)


def test_missing_required_field_rejected(tmp_path):
    modes_dir = _write_mode(tmp_path, "bad", (
        "id: bad\n"
        "persona: {system_prompt: prompts/stub.md}\n"
        "verifier: {type: evidence_chain}\n"))
    with pytest.raises(ModeError, match="budget"):
        load_mode("bad", modes_dir=modes_dir)


# ----------------------------------------------------------------------
# 4. capability 过滤：被禁工具不进 schema，也不可能被执行
# ----------------------------------------------------------------------
def test_denied_tool_absent_from_schema(tmp_path):
    registry = _registry("nuclei", "sqlmap", "http_test", "fscan")
    mode = load_mode("ctf-web")

    schemas = mode.tool_schemas(registry)
    names = [s["name"] for s in schemas]
    assert names == ["http_test"]            # 仅 allow 放行且未被 deny
    assert "nuclei" not in names and "sqlmap" not in names

    filtered = mode.filtered_registry(registry)
    assert filtered.get("nuclei") is None    # 执行前即不可达（机制性拦截）
    assert filtered.get("http_test") is not None
    assert registry.get("nuclei") is not None   # 原注册表不被破坏


def test_denied_tool_absent_from_agent_prompt(tmp_path):
    mode = load_mode("ctf-web")
    agent = _agent(tmp_path, mode, "nuclei", "http_test", "sqlmap")

    prompt = agent._system_prompt([])
    assert "http_test" in prompt
    assert "nuclei" not in prompt and "sqlmap" not in prompt
    assert agent.registry.get("sqlmap") is None


def test_pentest_mode_keeps_wildcard_but_blocks_denied(tmp_path):
    mode = load_mode("pentest-standard")
    agent = _agent(tmp_path, mode, "nuclei", "msf_exploit", "httpx")

    prompt = agent._system_prompt([])
    assert "nuclei" in prompt and "httpx" in prompt
    assert "msf_exploit" not in prompt       # allow 为 * 时仍受 deny 约束


# ----------------------------------------------------------------------
# 5. persona 注入
# ----------------------------------------------------------------------
def test_persona_injected_from_mode(tmp_path):
    mode = load_mode("ctf-web")
    with_mode = _agent(tmp_path / "with", mode, "http_test")
    assert with_mode._system_prompt([]).startswith("你是 XPentest")
    assert "CTF 比赛模式" in with_mode._system_prompt([])

    without_mode = _agent(tmp_path / "without", None, "http_test")
    assert "多模式" not in without_mode._system_prompt([])
    assert without_mode._system_prompt([]).startswith("你是 XPentest——一个 LLM")
