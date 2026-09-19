"""ModeProfile：多模式切换的一等公民（模式档案模型 + 加载器）。

- 模式定义在 `modes/*.yaml`，支持 `inherits` 单继承：**深合并**——子覆盖父，
  嵌套映射逐键合并，列表整体替换（不拼接）。
- 加载即校验：未知字段、缺字段、类型/枚举非法、继承缺失或成环，一律报错。
- 加载后不可变：冻结 dataclass + 只读映射，运行期无法改写。
- 校验为手写实现（stdlib dataclass），不引入 Pydantic（AGENTS.md 硬规则 5）。

字段语义见 AGENTS.md 第 4 节：persona / capability / permission / budget /
scope / verifier / skills / memory_namespace / sandbox。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional, Union

import yaml

from penagent.tools import ToolRegistry

MODES_DIRNAME = "modes"
DEFAULT_MODES_DIR = Path(__file__).resolve().parent.parent / MODES_DIRNAME

PERMISSION_LEVELS = ("ok", "ask", "deny")
VERIFIER_TYPES = ("evidence_chain", "flag_regex")
SANDBOX_LEVELS = ("none", "local", "docker")   # 与 penagent.sandbox 保持一致

_TOP_KEYS = {"id", "label", "inherits", "persona", "capability", "permission",
             "budget", "scope", "verifier", "skills", "memory_namespace",
             "sandbox", "triggers"}
_PERSONA_KEYS = {"system_prompt", "output_format"}
_CAPABILITY_KEYS = {"allow", "deny", "constraints"}
_PERMISSION_KEYS = {"default", "auto_approve", "require_confirm", "hard_deny"}
_BUDGET_KEYS = {"max_steps", "max_minutes", "max_cost_usd", "model_tier"}
_SCOPE_KEYS = {"target_allowlist", "network_egress"}
_VERIFIER_KEYS = {"type", "pattern", "auto_retry", "require_poc"}


class ModeError(ValueError):
    """模式定义非法（加载时抛出，附带出错文件与字段位置）。"""


# ----------------------------------------------------------------------
# 校验原语（手写：类型 + 枚举 + 未知字段）
# ----------------------------------------------------------------------
def _section(data: dict, key: str, allowed: set[str], where: str) -> dict:
    """取出子映射并校验：必须是映射、无未知键。"""
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ModeError(f"{where}: {key} 必须是映射，实际为 "
                        f"{type(value).__name__}")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ModeError(f"{where}: {key} 含未知字段 {unknown}"
                        f"（可用字段 {sorted(allowed)}）")
    return value


def _require(data: dict, key: str, where: str) -> Any:
    if key not in data:
        raise ModeError(f"{where}: 缺少必填字段 {key}")
    return data[key]


def _as_str(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModeError(f"{where}: 必须是非空字符串，实际为 {value!r}")
    return value.strip()


def _as_str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ModeError(f"{where}: 必须是字符串列表，实际为 "
                        f"{type(value).__name__}")
    return tuple(_as_str(item, f"{where}[]") for item in value)


def _as_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ModeError(f"{where}: 必须是布尔值，实际为 {value!r}")
    return value


def _as_number(value: Any, where: str,
               allow_none: bool = True) -> Optional[float]:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ModeError(f"{where}: 必须是数字，实际为 {value!r}")
    if value < 0:
        raise ModeError(f"{where}: 不能为负，实际为 {value!r}")
    return value


def _as_enum(value: Any, allowed: tuple[str, ...], where: str) -> str:
    text = _as_str(value, where)
    if text not in allowed:
        raise ModeError(f"{where}: 取值必须是 {allowed} 之一，实际为 {text!r}")
    return text


def _as_str_map(value: Any, where: str) -> Mapping[str, str]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, dict):
        raise ModeError(f"{where}: 必须是映射，实际为 {type(value).__name__}")
    items = {_as_str(k, f"{where}.key"): _as_str(v, f"{where}.{k}")
             for k, v in value.items()}
    return MappingProxyType(items)


# ----------------------------------------------------------------------
# 模式档案各段（冻结 dataclass = 运行期不可变）
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Persona:
    """提示词人格：system_prompt 为相对模式根目录的模板路径。"""

    system_prompt: str
    output_format: str


@dataclass(frozen=True)
class Capability:
    """工具白名单 / 黑名单 / 参数冻结。

    allow 支持 "*" 通配；deny 优先于 allow；allow 为空表示全部不可用
    （fail-closed，避免漏配即放行）。
    """

    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    constraints: Mapping[str, str] = MappingProxyType({})

    def allows(self, tool: str) -> bool:
        if tool in self.deny:
            return False
        if not self.allow:
            return False
        return "*" in self.allow or tool in self.allow

    def constraint_for(self, tool: str) -> str:
        """该模式的参数冻结串（无则空串），供工具执行前追加。"""
        return self.constraints.get(tool, "")

    def denial_reason(self, tool: str) -> str:
        if tool in self.deny:
            return f"工具 {tool} 被当前模式 capability.deny 禁用"
        if not self.allow:
            return "当前模式 capability.allow 为空，未放行任何工具"
        return (f"工具 {tool} 不在当前模式 capability.allow "
                f"{list(self.allow)} 内")


@dataclass(frozen=True)
class Permission:
    """权限档位：hard_deny > auto_approve > require_confirm > default。"""

    default: str = "ask"
    auto_approve: tuple[str, ...] = ()
    require_confirm: tuple[str, ...] = ()
    hard_deny: tuple[str, ...] = ()

    def level_for(self, tool: str) -> str:
        if tool in self.hard_deny:
            return "deny"
        if tool in self.auto_approve:
            return "ok"
        if tool in self.require_confirm:
            return "ask"
        return self.default


@dataclass(frozen=True)
class Budget:
    """预算策略：超限应换策略而非硬退出（主循环计数）。

    max_steps / max_minutes / model_tier 已生效（penagent/agent.py 主循环与
    LLM 档位路由）；max_cost_usd 为预留字段——OpenAI 兼容网关普遍不回传
    token 用量，可靠计量前不做硬约束，避免"看起来在算其实没生效"。
    """

    max_steps: int = 40
    max_minutes: Optional[float] = None
    max_cost_usd: Optional[float] = None
    model_tier: Mapping[str, str] = MappingProxyType({})


@dataclass(frozen=True)
class Scope:
    """目标范围与出网开关。

    target_allowlist 为空元组 = 声明为 "required"（必须运行期显式授权）。
    """

    target_allowlist: tuple[str, ...] = ()
    network_egress: bool = False

    @property
    def requires_explicit_allowlist(self) -> bool:
        return not self.target_allowlist


@dataclass(frozen=True)
class Verifier:
    """成功判定器：evidence_chain（渗透）或 flag_regex（CTF）。"""

    type: str = "evidence_chain"
    pattern: Optional[str] = None
    auto_retry: int = 0
    require_poc: bool = False

    def compiled_pattern(self) -> Optional[re.Pattern]:
        return re.compile(self.pattern) if self.pattern else None


@dataclass(frozen=True)
class ModeProfile:
    """模式档案：加载后不可变，供内核按模式裁决。"""

    id: str
    label: str
    persona: Persona
    capability: Capability
    permission: Permission
    budget: Budget
    scope: Scope
    verifier: Verifier
    memory_namespace: str
    sandbox: str
    skills: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()   # 关键词触发：任务文本命中即可推荐本模式
    inherits: Optional[str] = None
    source: str = ""        # 模式文件路径（诊断用）
    root: str = ""          # 模式根目录（persona.system_prompt 相对此解析）

    # ------------------------------------------------------------------
    @property
    def system_prompt_path(self) -> Path:
        return Path(self.root) / self.persona.system_prompt

    def read_system_prompt(self) -> str:
        """读取本模式的人格提示词模板（缺失即报错，不静默降级）。"""
        path = self.system_prompt_path
        if not path.is_file():
            raise ModeError(f"模式 {self.id}: 提示词模板不存在 {path}")
        return path.read_text(encoding="utf-8")

    def tool_allowed(self, tool: str) -> bool:
        return self.capability.allows(tool)

    def matches_keywords(self, text: str) -> list[str]:
        """任务文本命中的触发关键词（大小写不敏感的子串匹配）。"""
        lowered = (text or "").lower()
        return [k for k in self.triggers if k.lower() in lowered]

    def filtered_registry(self, registry: ToolRegistry) -> ToolRegistry:
        """按 capability 过滤出新的注册表：被禁用的工具既不进 schema，
        也无法在运行期被执行（机制性生效，非提示词约束）。

        沙箱策略与闸门一并带过去——过滤后的注册表若丢了这两样，换一条构造
        路径就成了绕过护栏的后门。
        """
        filtered = ToolRegistry(sandbox=getattr(registry, "sandbox", None),
                                gate=getattr(registry, "gate", None))
        for name in registry.names():
            if self.capability.allows(name):
                filtered.register(registry.get(name))
        return filtered

    def tool_schemas(self, registry: ToolRegistry) -> list[dict]:
        return self.filtered_registry(registry).schemas()


# ----------------------------------------------------------------------
# 加载器
# ----------------------------------------------------------------------
def _read_yaml(path: Path) -> dict:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ModeError(f"模式文件 {path} YAML 解析失败: {exc}") from exc
    if raw is None:
        raise ModeError(f"模式文件 {path} 为空")
    if not isinstance(raw, dict):
        raise ModeError(f"模式文件 {path} 顶层必须是映射")
    return raw


def _deep_merge(parent: dict, child: dict) -> dict:
    """深合并：嵌套映射逐键递归，列表/标量整体替换（子覆盖父）。"""
    merged = dict(parent)
    for key, value in child.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _mode_root(path: Path) -> Path:
    """模式根目录：modes/*.yaml -> 仓库根；其他布局 -> 模式文件所在目录。"""
    if path.parent.name == MODES_DIRNAME:
        return path.parent.parent
    return path.parent


def _build(data: dict, source: Path) -> ModeProfile:
    where = f"模式文件 {source}"

    unknown = sorted(set(data) - _TOP_KEYS)
    if unknown:
        raise ModeError(f"{where}: 含未知顶层字段 {unknown}"
                        f"（可用字段 {sorted(_TOP_KEYS)}）")

    mode_id = _as_str(_require(data, "id", where), f"{where}: id")
    label = _as_str(data.get("label", mode_id), f"{where}: label")
    inherits = data.get("inherits")
    if inherits is not None:
        inherits = _as_str(inherits, f"{where}: inherits")

    persona_raw = _section(data, "persona", _PERSONA_KEYS, where)
    persona = Persona(
        system_prompt=_as_str(_require(persona_raw, "system_prompt",
                                       f"{where}: persona"),
                              f"{where}: persona.system_prompt"),
        output_format=_as_str(persona_raw.get("output_format",
                                              "markdown_report"),
                              f"{where}: persona.output_format"),
    )

    cap_raw = _section(data, "capability", _CAPABILITY_KEYS, where)
    capability = Capability(
        allow=_as_str_list(cap_raw.get("allow"), f"{where}: capability.allow"),
        deny=_as_str_list(cap_raw.get("deny"), f"{where}: capability.deny"),
        constraints=_as_str_map(cap_raw.get("constraints"),
                                f"{where}: capability.constraints"),
    )

    perm_raw = _section(data, "permission", _PERMISSION_KEYS, where)
    permission = Permission(
        default=_as_enum(perm_raw.get("default", "ask"), PERMISSION_LEVELS,
                         f"{where}: permission.default"),
        auto_approve=_as_str_list(perm_raw.get("auto_approve"),
                                  f"{where}: permission.auto_approve"),
        require_confirm=_as_str_list(perm_raw.get("require_confirm"),
                                     f"{where}: permission.require_confirm"),
        hard_deny=_as_str_list(perm_raw.get("hard_deny"),
                               f"{where}: permission.hard_deny"),
    )

    budget_raw = _section(data, "budget", _BUDGET_KEYS, where)
    max_steps = _as_number(_require(budget_raw, "max_steps",
                                    f"{where}: budget"),
                           f"{where}: budget.max_steps", allow_none=False)
    if int(max_steps) != max_steps or max_steps < 1:
        raise ModeError(f"{where}: budget.max_steps 必须是正整数，"
                        f"实际为 {max_steps!r}")
    budget = Budget(
        max_steps=int(max_steps),
        max_minutes=_as_number(budget_raw.get("max_minutes"),
                               f"{where}: budget.max_minutes"),
        max_cost_usd=_as_number(budget_raw.get("max_cost_usd"),
                                f"{where}: budget.max_cost_usd"),
        model_tier=_as_str_map(budget_raw.get("model_tier"),
                               f"{where}: budget.model_tier"),
    )

    scope_raw = _section(data, "scope", _SCOPE_KEYS, where)
    allowlist_raw = scope_raw.get("target_allowlist")
    if allowlist_raw == "required":
        allowlist: tuple[str, ...] = ()   # 空 = 必须运行期显式授权
    else:
        allowlist = _as_str_list(allowlist_raw, f"{where}: scope.target_allowlist")
    scope = Scope(
        target_allowlist=allowlist,
        network_egress=_as_bool(scope_raw.get("network_egress", False),
                                f"{where}: scope.network_egress"),
    )

    verifier_raw = _section(data, "verifier", _VERIFIER_KEYS, where)
    verifier_type = _as_enum(_require(verifier_raw, "type", f"{where}: verifier"),
                             VERIFIER_TYPES, f"{where}: verifier.type")
    pattern = verifier_raw.get("pattern")
    if pattern is not None:
        pattern = _as_str(pattern, f"{where}: verifier.pattern")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ModeError(f"{where}: verifier.pattern 非法正则: {exc}") from exc
    if verifier_type == "flag_regex" and not pattern:
        raise ModeError(f"{where}: verifier.type=flag_regex 必须提供 pattern")
    auto_retry = _as_number(verifier_raw.get("auto_retry", 0),
                            f"{where}: verifier.auto_retry", allow_none=False)
    if int(auto_retry) != auto_retry or auto_retry < 0:
        raise ModeError(f"{where}: verifier.auto_retry 必须是非负整数")
    verifier = Verifier(
        type=verifier_type,
        pattern=pattern,
        auto_retry=int(auto_retry),
        require_poc=_as_bool(verifier_raw.get("require_poc", False),
                             f"{where}: verifier.require_poc"),
    )

    profile = ModeProfile(
        id=mode_id,
        label=label,
        inherits=inherits,
        persona=persona,
        capability=capability,
        permission=permission,
        budget=budget,
        scope=scope,
        verifier=verifier,
        memory_namespace=_as_str(data.get("memory_namespace", mode_id),
                                 f"{where}: memory_namespace"),
        sandbox=_as_enum(data.get("sandbox", "none"), SANDBOX_LEVELS,
                         f"{where}: sandbox"),
        skills=_as_str_list(data.get("skills"), f"{where}: skills"),
        triggers=_as_str_list(data.get("triggers"), f"{where}: triggers"),
        source=str(source),
        root=str(_mode_root(source)),
    )

    if not profile.system_prompt_path.is_file():
        raise ModeError(f"{where}: persona.system_prompt 指向的文件不存在 "
                        f"{profile.system_prompt_path}")
    return profile


def load_mode(mode: Union[str, Path],
              modes_dir: Optional[Union[str, Path]] = None) -> ModeProfile:
    """按 id 或文件路径加载模式，自动解析 inherits 链并合并校验。

    id 形式（如 "ctf-web"）在 modes_dir 下解析为 <id>.yaml；
    也接受直接的模式文件路径。
    """
    directory = Path(modes_dir) if modes_dir else DEFAULT_MODES_DIR
    path = Path(mode)
    if not path.is_file():
        path = directory / f"{mode}.yaml"
    if not path.is_file():
        raise ModeError(f"模式不存在：{mode}（已查找 {directory}）")

    chain: list[tuple[Path, dict]] = []
    visited: list[str] = []
    current = path
    while True:
        data = _read_yaml(current)
        chain.append((current, data))
        parent_id = data.get("inherits")
        if not parent_id:
            break
        key = str(parent_id)
        if key in visited:
            raise ModeError(f"模式 {path} inherits 链成环："
                            f"{' -> '.join(visited + [key])}")
        visited.append(key)
        current = current.parent / f"{parent_id}.yaml"
        if not current.is_file():
            raise ModeError(f"模式 {path} 的 inherits 目标不存在："
                            f"{parent_id}.yaml（已查找 {current.parent}）")

    merged: dict = {}
    for _, data in reversed(chain):      # 由根到叶依次覆盖
        merged = _deep_merge(merged, data)
    return _build(merged, path)


def load_modes(modes_dir: Optional[Union[str, Path]] = None
               ) -> dict[str, ModeProfile]:
    """加载目录下全部模式，返回 {id: ModeProfile}。"""
    directory = Path(modes_dir) if modes_dir else DEFAULT_MODES_DIR
    if not directory.is_dir():
        raise ModeError(f"模式目录不存在：{directory}")
    profiles: dict[str, ModeProfile] = {}
    for file in sorted(directory.glob("*.yaml")):
        profile = load_mode(file, modes_dir=directory)
        profiles[profile.id] = profile
    return profiles
