# Proteus · 千面 — Code Wiki

> 代码级导航文档：整体架构 / 模块职责 / 关键类与函数 / 依赖关系 / 运行方式。
> 事实来源为仓库源码本身；与 [AGENTS.md](../AGENTS.md)（AI 会话唯一事实来源）冲突时以 AGENTS.md 为准。
> 建议阅读顺序：第 1 章（概览）→ 第 2 章（架构与数据流）→ 第 4 章（模式层）→ 第 5 章（内核）→ 第 9 章（运行方式）。

- [1. 项目概览](#1-项目概览)
- [2. 架构总览与一次任务的数据流](#2-架构总览与一次任务的数据流)
- [3. 目录结构与文件清单](#3-目录结构与文件清单)
- [4. 模式层：ModeProfile](#4-模式层modeprofile)
- [5. 内核层模块详解（penagent/）](#5-内核层模块详解penagent)
- [6. 工具层（三层工具面与统一注册中心）](#6-工具层三层工具面与统一注册中心)
- [7. 宿主层：DSH preset 与 Web 控制台](#7-宿主层dsh-preset-与-web-控制台)
- [8. 依赖关系全景](#8-依赖关系全景)
- [9. 运行方式](#9-运行方式)
- [10. 数据与产物](#10-数据与产物)
- [11. 安全机制与不可违反的不变量](#11-安全机制与不可违反的不变量)
- [12. 测试体系与能力评测](#12-测试体系与能力评测)
- [13. 扩展指南](#13-扩展指南)
- [14. 已知限制与文档索引](#14-已知限制与文档索引)
- [附录 A：术语表](#附录-a术语表)

---

## 1. 项目概览

**一句话定位**：多模式渗透测试 Agent——同一套 Python 内核，通过 **ModeProfile（模式档案）** 在「常规渗透测试」「CTF 比赛」等场景之间**机制性**切换；工具白名单、参数冻结、权限档位、预算策略、成功判定器全部随模式生效，而不是写在提示词里靠模型自觉。

**技术路线（方案 C 为主线 + 方案 D 为宿主层）**：

| 层 | 内容 | 是否可独立运行 |
|---|---|---|
| 宿主层 | 双入口：自有 CLI / Python SDK；DSH（deepseek-harness）agent-preset 插件 | CLI 独立可跑（DSH 挂了不影响） |
| 模式层 | ModeProfile：`persona / capability / permission / budget / scope / verifier / skills / memory_namespace / sandbox` | 模式文件是纯数据，加载即校验 |
| 内核层 | `penagent/` 包：ReAct 决策循环 + 证据链反幻觉 + 记忆与技能进化 | 不依赖任何宿主 |
| 工具层 | MCP 统一注册（内置 function / 外部 CLI / 外部 MCP server 三类） | 新增能力不改内核代码 |
| 环境层 | Docker / WSL2 隔离、目标白名单硬校验、出网策略 | 模式可覆盖；容器不可用时**拒绝而非裸跑** |

**两条硬规则（贯穿全部设计）**：

1. **模式约束必须在工具执行前机制性生效**（禁用即拒绝执行），不能只写在 system prompt 里。
2. **可插拔 Verifier 是 CTF 与渗透的分水岭**：CTF 挂 `flag_regex`，渗透挂 `evidence_chain`；反幻觉（结论引用不存在的证据即判失败）是内核不变量，任何判定器都不可削弱。

**关键事实**：

| 项目 | 值 |
|---|---|
| 语言 / 运行时 | Python 3.12（Windows + bash；CI 覆盖 Windows 3.12/3.13 + Linux 实验性） |
| 运行时依赖 | 仅 PyYAML（`requirements.txt`）；Intranet 全栈以标准库实现 |
| 测试框架 | pytest（`pytest.ini` 只声明 `penagent` marker） |
| 测试基线（2026-09-24 实测） | 499 passed / 0 failed / 16 skipped（31 个用例文件；skip 全为容器类） |
| CLI 入口 | `python -m penagent <子命令>`（仓库无 pyproject/setup.py，不存在 `pentest` 命令） |
| 可移植性约定 | 入库文件零本机绝对路径；配置 JSON 写 `${VAR}`，真实值放不入库的 `.env`，由 `envcfg` 展开 |
| 默认授权范围 | 仅 `127.0.0.1` / `localhost` |

---

## 2. 架构总览与一次任务的数据流

### 2.1 分层装配关系

```
                          ┌───────────────────────────────┐
   宿主层（双入口）        │ CLI/SDK: python -m penagent   │  DSH: 三个 agent-preset
                          │ Web: web/server.py            │       + host 平面审计 bundle
                          └───────────────┬───────────────┘
                                          │ 都以 ModeProfile 为输入
                          ┌───────────────▼───────────────┐
   模式层                 │ ModeProfile（modes/*.yaml）    │  加载即校验、运行期不可变
                          └───────────────┬───────────────┘
                                          │
                          ┌───────────────▼───────────────┐
   内核层                 │ PenAgent（ReAct 循环）          │  modes.filtered_registry()
                          │  ├ Policy  ──► PolicyGate      │  工具面按模式裁剪
                          │  ├ EvidenceChain（链式哈希）    │
                          │  ├ Verifier（evidence_chain /  │
                          │  │            flag_regex）      │
                          │  └ Memory（按 namespace 分区）  │
                          └───────────────┬───────────────┘
                                          │ registry.execute()
                          ┌───────────────▼───────────────┐
   工具层                 │ ToolCenter（统一注册）          │  内置 function / 外部 CLI /
                          │  └ ToolRegistry（执行入口）     │  外部 MCP server 工具
                          └───────────────┬───────────────┘
                                          │ 执行前两道裁决（都在 execute() 内部）
                          ┌───────────────▼───────────────┐
   环境层                 │ PolicyGate（白名单/协议/授权）  │
                          │ SandboxPolicy（none/local/     │  容器不可用 → 拒绝
                          │                docker）        │
                          └───────────────────────────────┘
```

### 2.2 一次任务的完整生命周期（ReAct 主循环）

以 `PenAgent.run(target, objective)`（[agent.py](../penagent/agent.py#L524-L708)）为主线：

1. **建任务**：`memory.new_mission(target, objective)` 生成 mission_id，写 `data/missions/<ns>/<id>.json`；重复失败计数（R-39）在此按任务重置。
2. **检索技能**：`memory.find_skills(fingerprint)` → `_filter_mode_skills`（按 `mode.skills` 技能包过滤，[agent.py](../penagent/agent.py#L288-L303)）→ `_rank_skills`（默认按成功率降序；`stealth=True` 按 exposure 升序；RL 策略命中则置顶）。
3. **装配 system prompt**：`mode.read_system_prompt()` 读 `prompts/*.md`，替换 `{tools}`（已按模式裁剪的 `registry.schemas()`）与 `{skills}`。
4. **逐步骤循环**（上限 `mode.budget.max_steps`，无模式时 12）：
   - 时长预算检查：`max_minutes` 超限即跳出循环进入强制收口（换策略而非硬退出）。
   - `_decide(...)` 取决策（模型按 `budget.model_tier` 的 recon 档路由）：输出不可解析（`LLMOutputError`）时回灌"只输出一个 JSON 对象"提示并重试 `LLM_PARSE_RETRY_LIMIT` 次——**解析失败不记步数**，每次失败留证（`phase=llm_parse_retry`，含原始输出片段），连续到上限才收口；调用失败（网络/HTTP/超时）不在此重试（R-40）。
   - 决策为 `done` → 交 `verifier.verify(decision, evidence, context=本任务期间工具输出)`：
     - 反幻觉不过 → 直接失败（不可重试）；判定未过但可重试 → 回灌原因继续循环。
     - 通过 → 记 `conclusion` 证据、`memory.finish(...)`、回写技能成功率、返回 `MissionResult`。
   - 决策为工具调用 → `policy.apply_constraints`（模式冻结参数并入 args）→ `registry.get(tool)` 查不到即给出**机制性拒绝原因** → `policy.check` 护栏裁决 → **重复失败检测**（`_loop_reason`：同工具 + 同参数连续失败到 `REPEAT_FAILURE_LIMIT` 即拦下并回灌"上次失败原因 + 换思路"，记 `blocked=True / level="loop"`）→ `registry.execute` → 证据固化（`tool_call`）→ 作战记录追加步骤 → 结果回灌消息。
5. **预算耗尽收口**：追加一轮「不要再调工具，基于已有证据给结论」，用 reason 档模型收口，再交判定器；仍未通过则如实失败。

---

## 3. 目录结构与文件清单

```
proteus-agent/
├── AGENTS.md                     AI 会话唯一事实来源（硬规则/环境约定/模式规范）
├── README.md                     项目主页（定位/路线/快速开始）
├── conftest.py                   pytest 会话配置：07 靶场路径解析 + 测试用 local 档沙箱注入
├── pytest.ini                    pytest 配置（markers）
├── requirements.txt              依赖清单（PyYAML + pytest；torch 为可选，刻意不列入）
├── .env.example                  .env 模板（LLM 三键 + 本机路径 + 沙箱镜像）
├── penagent/                     内核包（详见第 5、6 章）
├── modes/                        模式档案（base / pentest-standard / ctf-web / ctf-crypto）
├── prompts/                      模式人格提示词（pentest.md / ctf.md / dsh-persona*.md）
├── dsh/                          DSH agent-preset 模板 + 共享插件 + 启动器 + host 平面桥
├── web/                          Web 控制台（server.py + static/）
├── examples/                     评测与演示脚本（benchmark / eval_* / lab* / train_* / target）
├── tests/                        31 个 pytest 用例文件 + 桩 MCP server
├── tools/                        维护脚本（dsh_install / scrub_paths / md2html / 镜像构建 …）
├── docker/                       沙箱镜像 + 7 个容器化 MCP server
├── data/                         运行时数据（gitignore）：作战记录/技能/证据链/评测产物
└── docs/                         调研、设计、验收与真机实测记录
```

**内核包文件清单**（`penagent/`，按职责分组）：

| 分组 | 文件 | 职责一句话 |
|---|---|---|
| 决策 | [agent.py](../penagent/agent.py) | ReAct 主循环 + Policy 安全护栏 |
| 模式 | [modes.py](../penagent/modes.py) | ModeProfile 模型 / 加载器 / 校验 |
| 护栏 | [policy_gate.py](../penagent/policy_gate.py) | 工具执行闸门（白名单 + 协议 + 高危授权） |
| 证据 | [evidence.py](../penagent/evidence.py) | 链式哈希证据链（JSONL 追加写） |
| 判定 | [verifier.py](../penagent/verifier.py) | 可插拔成功判定器 + 反幻觉底线 |
| 工具 | [tools.py](../penagent/tools.py) | ToolSpec / ToolResult / ToolRegistry |
| 工具 | [registry.py](../penagent/registry.py) | ToolCenter 统一注册中心 + `build_center()` |
| 工具 | [builtin_tools.py](../penagent/builtin_tools.py) | 内置被动侦察与 HTTP 原始证据工具 |
| 工具 | [http_session.py](../penagent/http_session.py) | 会话态 HTTP（cookie jar）+ 请求重放 |
| 工具 | [external_tools.py](../penagent/external_tools.py) + `.json` | 外部 CLI 工具配置化注册 |
| 工具 | [ctf_tools.py](../penagent/ctf_tools.py) + `.json` | CTF 解码链 / 文件识别 / RsaCtfTool / 沙箱脚本 |
| 工具 | [mcp.py](../penagent/mcp.py) | 本内核作为 MCP Server（stdio） |
| 工具 | [mcp_client.py](../penagent/mcp_client.py) | 外部 MCP server 客户端（stdio/http） |
| 隔离 | [sandbox.py](../penagent/sandbox.py) | 沙箱分档 + DockerRunner + 容器路径重写 |
| 记忆 | [memory.py](../penagent/memory.py) | 作战记录 + 经验库（按 namespace 分区） |
| 记忆 | [reflect.py](../penagent/reflect.py) | 任务后 LLM 复盘 → 技能沉淀 |
| 记忆 | [skill_seeds.py](../penagent/skill_seeds.py) | 预置技能种子（幂等写入） |
| 记忆 | [skill_export.py](../penagent/skill_export.py) | 经验库 → DSH 扁平 Markdown 技能 |
| 进化 | [rl.py](../penagent/rl.py) / [ppo.py](../penagent/ppo.py) | Q-learning / PPO 技能选择策略 |
| 分析 | [gaps.py](../penagent/gaps.py) | 工具使用统计与能力盲区 |
| 报告 | [report.py](../penagent/report.py) | 人读汇总 / 层级视图 / SARIF 2.1.0 |
| 支撑 | [scope.py](../penagent/scope.py) | 会话授权目标（只有人能写） |
| 支撑 | [llm.py](../penagent/llm.py) | OpenAI 兼容客户端 + 档位模型路由 |
| 支撑 | [envcfg.py](../penagent/envcfg.py) | `.env` 装载 + `${VAR}` 展开 + 路径脱敏原语 |
| 支撑 | [dsh_bridge.py](../penagent/dsh_bridge.py) | DSH 会话事件 spool → 内核证据链 |
| 支撑 | [cli.py](../penagent/cli.py) / `__main__.py` / `__init__.py` | CLI 入口与包初始化 |
| 适配 | [adapters/rayscan.py](../penagent/adapters/rayscan.py) / [adapters/packetforge.py](../penagent/adapters/packetforge.py) | RayScan wvs 库 / PacketForge nmap 能力接入 |

---

## 4. 模式层：ModeProfile

模式定义在 `modes/*.yaml`，支持 `inherits` **单继承 + 深合并**（嵌套映射逐键合并、列表整体替换）；**加载即校验**（未知字段、缺字段、类型/枚举非法、继承缺失或成环一律报错）；**加载后不可变**（冻结 dataclass + `MappingProxyType`）。校验为手写实现，不引入 Pydantic（硬规则 5）。

### 4.1 字段语义与生效点

| 字段 | 语义 | 生效点（代码位置） |
|---|---|---|
| `persona.system_prompt` | 相对模式根的提示词模板路径 | `ModeProfile.read_system_prompt()` |
| `persona.output_format` | 输出形态声明（`markdown_report` / `raw_flag`） | 提示词层 |
| `capability.allow / deny / constraints` | 工具白名单 / 黑名单 / 参数冻结串 | `Policy.check` + `ModeProfile.filtered_registry` |
| `permission.default / auto_approve / require_confirm / hard_deny` | `ok / ask / deny` 档位 | `Policy.check` 与 `PolicyGate` |
| `budget.max_steps / max_minutes / model_tier` | 步数 / 时长 / 模型档位 | `PenAgent.run` 主循环；`_tier_model()` |
| `budget.max_cost_usd` | **预留字段**（网关普遍不回传 token 用量，可靠计量前不做硬约束） | 暂不消费 |
| `scope.target_allowlist / network_egress` | 目标范围 / 出网开关 | `Policy._narrow_by_mode`、出网闸门、`SandboxPolicy(egress=...)` |
| `verifier.type / pattern / auto_retry / require_poc` | 成功判定器 | `build_verifier()` |
| `skills` | 本模式技能包（按 `Skill.category` 过滤注入） | `PenAgent._filter_mode_skills` |
| `memory_namespace` | 记忆/技能库分区 | `Memory.for_namespace` |
| `sandbox` | 隔离档位（`none / local / docker`） | `SandboxPolicy.decide` |
| `triggers` | 关键词触发（任务文本命中即推荐本模式） | `ModeProfile.matches_keywords`（Web 控制台 / 命令） |
| `inherits` | 父模式 id（单继承，链式解析并检测成环） | `load_mode` |

### 4.2 关键类与函数（[modes.py](../penagent/modes.py)）

| 符号 | 位置 | 说明 |
|---|---|---|
| `ModeError(ValueError)` | [L58](../penagent/modes.py#L58) | 模式定义非法（附出错文件与字段位置） |
| `_matches(pattern, tool)` / `_any_match(...)` | [L43-L55](../penagent/modes.py#L43-L55) | 工具名匹配：精确名或 `fnmatch` 通配（`*`、`chameleon_*`） |
| `Persona(system_prompt, output_format)` | [L136](../penagent/modes.py#L136) | 冻结 dataclass |
| `Capability(allow, deny, constraints)` | [L144](../penagent/modes.py#L144) | `allows(tool)` / `constraint_for(tool)` / `denial_reason(tool)`；**deny 优先**，allow 为空 = 全禁（fail-closed） |
| `Permission(default, auto_approve, require_confirm, hard_deny)` | [L184](../penagent/modes.py#L184) | `level_for(tool)`：`hard_deny > auto_approve > require_confirm > default` |
| `Budget(max_steps, max_minutes, max_cost_usd, model_tier)` | [L207](../penagent/modes.py#L207) | 默认 `max_steps=40` |
| `Scope(target_allowlist, network_egress)` | [L222](../penagent/modes.py#L222) | 空 allowlist = "required"（运行期必须显式授权） |
| `Verifier(type, pattern, auto_retry, require_poc)` | [L237](../penagent/modes.py#L237) | `compiled_pattern()` |
| `ModeProfile` | [L250](../penagent/modes.py#L250) | `system_prompt_path` / `read_system_prompt()` / `tool_allowed()` / `matches_keywords(text)` / `filtered_registry(registry)` / `tool_schemas(registry)` |
| `load_mode(mode, modes_dir=None)` | [L464](../penagent/modes.py#L464) | 按 id 或路径加载，解析 inherits 链后深合并再校验 |
| `load_modes(modes_dir=None)` | [L503](../penagent/modes.py#L503) | 加载目录下全部模式（`{id: ModeProfile}`） |
| `_deep_merge(parent, child)` / `_mode_root(path)` / `_build(data, source)` | [L323](../penagent/modes.py#L323) 起 | 合并、根目录推导（`modes/*.yaml` → 仓库根）、逐字段校验构造 |

**机制性裁剪的关键实现**：`ModeProfile.filtered_registry()`（[L290-L302](../penagent/modes.py#L290-L302)）返回一个**新的** `ToolRegistry`，只装 `capability.allows(name)` 为真的工具，并把沙箱策略与闸门一并带过去。效果是：被模式禁用的工具**既不进 system prompt 的工具 schema，也无法在运行期被执行**（换一条构造路径也绕不过）。

### 4.3 出厂模式对照

| 项 | base | pentest-standard | ctf-web | ctf-crypto |
|---|---|---|---|---|
| 提示词 | `prompts/pentest.md` | 同左 | `prompts/ctf.md` | `prompts/ctf.md` |
| 继承 | — | base | base | base |
| capability.allow | `["*"]` | `["*"]` | 真名 + 前缀通配（见下） | 真名 + 前缀通配 |
| capability.deny | 空 | `msf_exploit` / `webshell_write` | nuclei/fscan/sqlmap/ffuf 等 | 同左 |
| constraints | 空 | `nuclei` / `sqlmap` / `fscan` 参数冻结 | — | — |
| permission.default | ask | ask | ask | ask |
| budget.max_steps | 40 | 40 | 60 | 60 |
| budget.max_minutes | 180 | 180 | 20 | 20 |
| scope.network_egress | false | **true**（渗透必须触达目标） | true | true |
| verifier | evidence_chain | `evidence_chain, require_poc: true` | `flag_regex (?i)(flag\|ctf)\{[^}]+\}, auto_retry: 3` | 同 ctf-web |
| sandbox | docker | docker | docker | docker |
| memory_namespace | base | pentest-standard | ctf-web | ctf-crypto |

要点：

- `base.yaml` **刻意不写 `verifier.require_poc`**（否则深合并会泄漏进 CTF 模式）；也刻意不作为可运行模式（Web 控制台与 `/proteus-mode` 都会跳过 `base`）。
- `capability.allow` **只写真名或前缀通配**：`allow` 是精确匹配（`fnmatch`），写抽象契约名会**静默拒绝**（历史上 "CTF 模式连 http_raw 都发不出去" 即由此而来，见 [ctf-web.yaml](../modes/ctf-web.yaml#L6-L19) 注释）。真名清单由 `tests/test_modes.py` 的核对用例钉住。
- `permission.require_confirm / hard_deny` 允许写「尚未安装但一旦出现必须先拦」的前瞻名（死条目只增加摩擦，不会静默放行）。

---

## 5. 内核层模块详解（penagent/）

### 5.1 [agent.py](../penagent/agent.py) — ReAct 主循环 + 安全护栏

| 符号 | 位置 | 签名 / 要点 |
|---|---|---|
| `SYSTEM_PROMPT` | [L21](../penagent/agent.py#L21) | 无模式时的默认提示词模板（含 `{tools}` / `{skills}` 占位符） |
| `REPEAT_FAILURE_LIMIT` | [L46](../penagent/agent.py#L46) | 内核侧重复失败检测阈值（缺省 3）：同工具 + 同参数连续失败到此数即拦（R-39；刻意不做成 ModeProfile 字段） |
| `LLM_PARSE_RETRY_LIMIT` | [L57](../penagent/agent.py#L57) | LLM 输出不可解析时的重试上限（缺省 3，共 4 次尝试）：回灌"只输出一个 JSON 对象"提示并重试，**不记步数**（R-40；同样刻意不做成 ModeProfile 字段） |
| `MissionResult` | [L61](../penagent/agent.py#L61) | `mission_id / target / objective / outcome(success\|failed\|blocked) / steps / summary / evidence_refs / injected_skills / reflection` + `to_dict()` |
| `Policy` | [L76](../penagent/agent.py#L76) | 模式能力/权限裁决 + 授权目标 + 高危确认；规则写死，不参与决策 |
| `Policy.normalize_targets(value)` | [L98](../penagent/agent.py#L98) | 静态方法：`"a,b"` 或可迭代 → 列表；**必须做**（字符串本身是 iterable，`list("127.0.0.1")` 会炸成单字符列表把白名单打成筛子）；空值回落 `["127.0.0.1","localhost"]` |
| `Policy._narrow_by_mode(runtime_targets, mode)` | [L119](../penagent/agent.py#L119) | 模式白名单**只可收紧**：与运行期显式授权取交集 |
| `Policy.bind_mode(mode)` | [L132](../penagent/agent.py#L132) | 返回挂载模式裁决的副本（不改原实例） |
| `Policy.level_for(tool, spec=None)` | [L137](../penagent/agent.py#L137) | `ok / ask / deny` 档位 |
| `Policy.apply_constraints(tool, args)` | [L148](../penagent/agent.py#L148) | 把模式冻结参数写进 `FROZEN_ARGS_KEY`（执行前机制性生效） |
| `Policy.check(tool, spec, args) -> (bool, str)` | [L164](../penagent/agent.py#L164) | 裁决顺序：capability 禁用 → permission `deny` → `ask` 未授权 → 出网开关 → 高危未授权 → `host/url/domain/target/base_url` 白名单；拒绝理由带**授权指引**（`/proteus-scope add ...`，「模型不能自我授权」） |
| `Policy._in_scope(value)` | [L201](../penagent/agent.py#L201) | URL / `host:port` / 路径三种形态归一后按 `host == t or host.endswith("." + t)` 匹配 |
| `PenAgent.__init__(...)` | [L217](../penagent/agent.py#L217) | 见下方装配清单 |
| `PenAgent._fingerprint(tool, args)` | [L366](../penagent/agent.py#L366) | 静态方法：调用指纹 = 工具名 + `json.dumps(sort_keys=True)` 规范化参数（键序无关，与宿主侧 supervisor 同构） |
| `PenAgent._loop_reason(tool, args)` | [L379](../penagent/agent.py#L379) | 连续失败达阈值即返回纠正指令文案（含上次失败原因 + 换思路），否则空串；命中即拒绝执行（R-39） |
| `PenAgent._record_tool_outcome(tool, args, result)` | [L401](../penagent/agent.py#L401) | 失败累加、成功清零（**只清本指纹**，避免"交替失败"躲过判据） |
| `PenAgent._parse_correction(exc)` | [L419](../penagent/agent.py#L419) | 静态方法：把 `LLMOutputError` 转成回灌给模型的纠正提示（点名禁 XML/工具调用标签 + 附上次输出片段） |
| `PenAgent._decide(messages, mission_id, step, model=None)` | [L435](../penagent/agent.py#L435) | 取一步决策；`LLMOutputError` → 留证（`phase=llm_parse_retry`）+ 回灌提示 + 重试到 `LLM_PARSE_RETRY_LIMIT`；`LLMError`（调用失败）直接上抛（R-40） |
| `PenAgent.run(target, objective, fingerprint="", stealth=False)` | [L524](../penagent/agent.py#L524) | 主循环（第 2.2 节） |

**`PenAgent.__init__` 的装配语义（每条都是硬约束的落点）**：

1. 判定器：显式传入 > `build_verifier(mode.verifier)` > `EvidenceChainVerifier()`。
2. 工具面：`mode.filtered_registry(registry)`；注册表缺沙箱时补 `build_sandbox(mode.sandbox, egress=mode.scope.network_egress)`。
3. 记忆分区：`memory.for_namespace(mode.memory_namespace)`。
4. 闸门：注册表无 `gate` 时挂 `PolicyGate(self.policy)`（**闸门挂在注册表而不是 run() 里**——因此 ReAct 循环、MCP 底层工具、Web 子进程全部绕不过）。
5. 预算：`max_steps` 显式传参 > `mode.budget.max_steps` > 12；`max_minutes` 来自模式。
6. 事件回调：`on_event`（fail-open，异常被吞）。

**私有方法与用途**：`_record_skill_outcomes(success)`（把任务结果回写到本任务复用的技能）、`_filter_mode_skills(skills)`、`_rank_skills(skills, fingerprint, stealth)`、`_append_evidence(kind, mission_id, step, content)`（带任务归属留证）、`_blocked(...)`（拦截留痕 + 回灌消息）、`_mission_context(since_seq)`（本任务期间工具输出原文，供按输出判定的判定器）、`_system_prompt(skills)`、`_tier_model(phase)`（recon/reason → cheap/strong → 模型 id）、`_emit(**event)`、`_finish(mission)`。

### 5.2 [policy_gate.py](../penagent/policy_gate.py) — 工具执行闸门

| 符号 | 位置 | 说明 |
|---|---|---|
| `ALLOWED_SCHEMES = ("http","https")` / `TARGET_KEYS` | [L23-L26](../penagent/policy_gate.py#L23-L26) | 协议白名单；承载目标的参数名 |
| `GateDecision(allowed, reason, rule, level)` | [L37](../penagent/policy_gate.py#L37) | `rule ∈ {scheme, allowlist, dangerous, mode, policy}`；`level ∈ {ok, ask, deny}` |
| `PolicyGate(policy)` / `check(spec, args=None)` | [L47](../penagent/policy_gate.py#L47) | 先协议白名单，再交 `Policy.check` |
| `_scheme_reason(args)` | [L68](../penagent/policy_gate.py#L68) | 带 `://` 的目标值只允许 http/https |
| `_rule_of(reason)` / `_level(spec)` | [L84](../penagent/policy_gate.py#L84) | 仅用于审计标签与审批展示 |

**存在理由**（文件头注释）：升级前白名单校验只在 `PenAgent.run` 里调用，而 MCP 底层工具分支直连 `registry.execute()`，导致 `--targets` 形同虚设（实测越界目标照常执行）。现在闸门由 `ToolRegistry` 持有、裁决发生在 `execute()` 内部，任何调用方都绕不过去。**授权来源只来自持有闸门的一方（操作员），调用参数里的 `authorize` 一律不生效**。

### 5.3 [evidence.py](../penagent/evidence.py) — 链式哈希证据链

| 符号 | 位置 | 说明 |
|---|---|---|
| `sha256(data)` | [L17](../penagent/evidence.py#L17) | 哈希原语 |
| `EvidenceRecord` | [L22](../penagent/evidence.py#L22) | `seq / kind(decision\|tool_call\|observation\|conclusion) / content / timestamp / prev_hash / hash`；`canonical()`（`sort_keys` 规范化 JSON）、`compute_hash()`、`to_dict()`、`from_dict()` |
| `EvidenceChain(path="data/chain.jsonl")` | [L50](../penagent/evidence.py#L50) | JSONL 追加写 |
| `.append(kind, content) -> EvidenceRecord` | [L59](../penagent/evidence.py#L59) | 引用前序哈希后落盘 |
| `.tail()` / `.load()` | [L72](../penagent/evidence.py#L72) | 取末条 / 全量加载 |
| `.verify() -> dict` | [L83](../penagent/evidence.py#L83) | 返回 `{ok, length, tampered, broken_links}`：自身哈希 + `prev_hash` 链双重校验 |
| `.refs(seqs)` / `.valid_refs(seqs)` | [L99](../penagent/evidence.py#L99) | 按 seq 取内容 / 过滤出真实存在的 seq（**反幻觉校验的实现**） |

### 5.4 [verifier.py](../penagent/verifier.py) — 可插拔成功判定器

| 符号 | 位置 | 说明 |
|---|---|---|
| `VerificationResult(ok, reason, retryable, evidence_refs)` | [L19](../penagent/verifier.py#L19) | 判定结果（冻结 dataclass） |
| `_check_refs(decision, evidence)` | [L28](../penagent/verifier.py#L28) | 反幻觉校验：非法引用值按「不存在」计，不做静默丢弃 |
| `Verifier(auto_retry=0)` | [L46](../penagent/verifier.py#L46) | 基类：`reset()` / `attempts` / `verify(decision, evidence, context="")` / `_judge(...)`（子类实现） |
| `EvidenceChainVerifier(require_poc=False, auto_retry=0)` | [L93](../penagent/verifier.py#L93) | 渗透模式：`require_poc` 时结论必须带证据引用 |
| `FlagRegexVerifier(pattern, auto_retry=0)` | [L109](../penagent/verifier.py#L109) | CTF 模式：在「结论 + 本任务期间工具输出」语料上搜 flag；未命中且尚有重试次数则 `retryable=True` |
| `build_verifier(spec)` | [L137](../penagent/verifier.py#L137) | 按模式 `verifier` 段构造（模式与实现解耦） |

**内核不变量**：任何模式、任何判定器，结论引用不存在的证据一律判失败**且不给重试**（硬规则 2）。

### 5.5 [memory.py](../penagent/memory.py) — 记忆底座（按分区）

| 符号 | 位置 | 说明 |
|---|---|---|
| `Skill` | [L31](../penagent/memory.py#L31) | `id / title / target_fingerprint / steps / tools / evidence_refs / evidence_text / category / success_rate / successes / attempts / exposure / source_mission / created_at`；`record_outcome(success)` 更新成功率 |
| `Memory(root="data", namespace=DEFAULT_NAMESPACE)` | [L65](../penagent/memory.py#L65) | 目录：`<root>/missions/<ns>/` 与 `<root>/skills/<ns>/` |
| `for_namespace(ns)` / `namespaces()` | [L77](../penagent/memory.py#L77) / [L81](../penagent/memory.py#L81) | 分区切换 / 已存在分区枚举 |
| `locate_mission(root, mission_id)`（classmethod） | [L91](../penagent/memory.py#L91) | **跨分区定位任务** → `(namespace, 记录)`；拒绝路径分隔符与 `..`。`reflect` / `pentest_reflect` 靠它读模式分区任务（R-37） |
| `new_mission(target, objective)` | [L123](../penagent/memory.py#L123) | 生成 8 位 uuid mission_id 并落盘 |
| `add_step(mission_id, step)` / `finish(mission_id, outcome, reflection="", evidence_refs=None)` | [L134](../penagent/memory.py#L134) / [L139](../penagent/memory.py#L139) | 作战记录生命周期（`finish` 会把结论引用写进记录） |
| `get_mission` / `list_missions` | [L152](../penagent/memory.py#L152) / [L155](../penagent/memory.py#L155) | 读单条 / 全部分区记录 |
| `add_skill` / `update_skill` / `list_skills(sort_by_rate=False, sort_by_stealth=False, category="")` | [L172](../penagent/memory.py#L172) / [L177](../penagent/memory.py#L177) / [L185](../penagent/memory.py#L185) | 经验库 CRUD 与排序 |
| `find_skills(fingerprint)` | [L204](../penagent/memory.py#L204) | 关键词共现匹配（忽略纯数字 token，如 IP 段） |
| `recent_skills(limit=5)` | [L223](../penagent/memory.py#L223) | 最近技能 |

分区名经 `_safe_namespace()` 校验（仅 `[A-Za-z0-9._-]`，拒绝路径穿越）。**模式间不互串**：渗透沉淀的技能不会被 CTF 任务检索到。

### 5.6 进化链路：[reflect.py](../penagent/reflect.py) / [skill_seeds.py](../penagent/skill_seeds.py) / [skill_export.py](../penagent/skill_export.py) / [gaps.py](../penagent/gaps.py) / [rl.py](../penagent/rl.py) / [ppo.py](../penagent/ppo.py)

| 模块 | 关键符号 | 说明 |
|---|---|---|
| reflect.py | `REFLECT_PROMPT`（[L16](../penagent/reflect.py#L16)）、`Reflector(llm=None).reflect(mission_id, memory, evidence) -> (analysis, Skill\|None)`（[L46](../penagent/reflect.py#L46)） | LLM 复盘产出成败归因与可复用技能；**技能入库前校验 `evidence_refs` 真实存在**，否则拒绝入库 |
| skill_seeds.py | `SEED_SKILLS`（[L36](../penagent/skill_seeds.py#L36)）、`seed_skills(memory, refresh=False)`（[L117](../penagent/skill_seeds.py#L117)） | 预置技能（产品知识）幂等写入；`refresh=True` 覆盖正文但保留学习统计 |
| skill_export.py | `export_skills(data_dir, out_dir, namespace="")`（[L85](../penagent/skill_export.py#L85)） | 导出为 `<namespace>-<id8>.md` + YAML frontmatter（对齐 DSH 扁平技能发现），供 preset 的 `customSkillDirs` 消费 |
| gaps.py | `analyze_gaps(memory, evidence=None)`（[L15](../penagent/gaps.py#L15)）、`analyze_gaps_llm(memory, llm=None)`（[L85](../penagent/gaps.py#L85)） | 工具调用热力 / 失败率 / 拦截次数（`blocked` 与 `loop` 分列——循环拦截不是"高危未授权"，建议文案各说各的）→ 规则化建议；LLM 模式产出能力盲区清单 |
| rl.py | `SkillPolicy`（[L20](../penagent/rl.py#L20)） | 轻量 Q-learning：ε-greedy 选技能、Q 表更新、`best_skill(fingerprint)`、JSON 持久化 |
| ppo.py | `state_key / state_id / state_feature / feature_state`（[L28-L51](../penagent/ppo.py#L28-L51)）、`ActorCritic(nn.Module)`（[L57](../penagent/ppo.py#L57)）、`PPOSkillPolicy`（[L83](../penagent/ppo.py#L83)） | PPO clip 训练 + `.pt` 持久化；`torch` 为**可选依赖**（未安装时相关用例 `importorskip` 跳过） |

RL 链路实测（2026-09-18，见 `docs/RL链路实测记录.md`）：`eval_evolution.py` 决策步数 6.0 → 3.0（-50%）；`eval_closed_loop.py` 基线 4.28 → Q 学习 2.60（-39%）→ PPO 2.50（-42%），三次重跑逐位一致。

### 5.7 支撑模块

| 模块 | 关键符号 | 说明 |
|---|---|---|
| [scope.py](../penagent/scope.py) | `SESSION_SCOPE_FILE`、`scope_path(data_dir, key="")`、`read_scope` / `write_scope` / `add_targets` / `remove_targets` / `clear_scope`（[L71-L116](../penagent/scope.py#L71-L116)） | 会话授权清单（`data/session-scope[-<key>].json`）。**内核从不写这个文件**：写入口只有 CLI 与 DSH 命令插件；读失败一律回落空清单（不阻塞、不静默放行）。与 `--targets` 取并集 |
| [llm.py](../penagent/llm.py) | `LLMConfig`（[L52](../penagent/llm.py#L52)）、`LLMError`（[L94](../penagent/llm.py#L94)）、`LLMOutputError`（[L98](../penagent/llm.py#L98)，输出不可解析，带 `raw`，R-40）、`chat(...)`（[L115](../penagent/llm.py#L115)）、`_extract_json_block(text)`（[L184](../penagent/llm.py#L184)）、`chat_json(...)`（[L221](../penagent/llm.py#L221)）、`_allow_endpoint(base_url)`（[L29](../penagent/llm.py#L29)） | OpenAI 兼容 `/chat/completions`；503/429 退避重试；读超时单独兜住（不复用连接分支）；端点仅 http(s) 且拒绝链路本地/组播/保留段；`tier_models` 承载 cheap/strong 档位模型；`session_id` 作为 `x-opencode-session` 头 |
| [envcfg.py](../penagent/envcfg.py) | `read_env_file` / `load_env_file` / `expand(value)` / `expand_deep(obj)` / `local_needles()` / `local_path_pattern(value)` / `scrub_local_paths(text)` / `find_local_paths(text)` / `resolve_g07()` / `ensure_g07_on_path()`（[L23-L172](../penagent/envcfg.py#L23-L172)） | `.env` 装载与 `${VAR}` 展开（未定义变量原样保留）；路径脱敏原语（`tools/scrub_paths.py` 与 `tests/test_path_hygiene.py` 共用同一份解析）；07 靶场路径解析并注入 `sys.path` + `PYTHONPATH` |
| [report.py](../penagent/report.py) | `evidence_report(data_dir, mission_id="")`（[L308](../penagent/report.py#L308)）、`mission_tree(data_dir, mission_id="")`（[L69](../penagent/report.py#L69)）、`render_tree(tree)`（[L194](../penagent/report.py#L194)）、`sarif_report(data_dir, mission_id="")`（[L236](../penagent/report.py#L236)）、`SARIF_LEVELS`、`_all_missions(data_dir)` | 人读汇总（CLI `evidence` 与 MCP `pentest_evidence` 共用一份实现）；扁平链 → Task→Action→Artifact 层级视图（无归属记录进 `unlinked`，不静默丢）；SARIF 2.1.0（一条证据 = 一条 result，`ruleId = proteus/<kind>`，**不是漏洞报告**） |
| [dsh_bridge.py](../penagent/dsh_bridge.py) | `DEFAULT_SPOOL` / `DEFAULT_STATE`、`import_spool(spool, chain=None, chain_path="data/chain.jsonl", state_path=DEFAULT_STATE, replay=False, flush_open=False)`（[L92](../penagent/dsh_bridge.py#L92)）、`_pair_result(pending, event, call_id)`（[L66](../penagent/dsh_bridge.py#L66)）、`_read_new_lines(spool, offset)`（[L46](../penagent/dsh_bridge.py#L46)） | 把宿主桥 spool 并入内核链式哈希证据链：**链式哈希只在内核实现一份**；`call` 与 `result` 按 callId 三级匹配配对合并为一条 `tool_call`（形状与内核自有记录一致）；按字节偏移增量导入，未配对调用跨导入持久化，`flush_open` 收尾 |

### 5.8 [cli.py](../penagent/cli.py) — 命令行入口

`main(argv)`（[L352](../penagent/cli.py#L352)）装配 argparse 子命令，每个 `cmd_*` 返回退出码。

| 子命令 | 处理函数 | 作用 |
|---|---|---|
| `run` | `cmd_run`（[L77](../penagent/cli.py#L77)） | 执行任务（LLM 决策）；`--target / --objective / --fp / --authorize / --stealth / --targets / --mode / --max-steps / --data / --rl-policy / --discover-mcp / --discover-budget` |
| `reflect` | `cmd_reflect`（[L100](../penagent/cli.py#L100)） | 任务后反思 → 技能沉淀 |
| `agents` | `cmd_agents`（[L114](../penagent/cli.py#L114)） | 列出工具（构建与内核同款注册表，两层过滤都生效） |
| `skills` | `cmd_skills`（[L160](../penagent/cli.py#L160)） | 经验库列表；`--seed` 写种子、`--export/--out/--export-namespace` 导出 DSH 技能、`--mode` 指定分区 |
| `missions` | `cmd_missions`（[L203](../penagent/cli.py#L203)） | 作战记录列表 |
| `evidence` | `cmd_evidence`（[L211](../penagent/cli.py#L211)） | 证据链 + 作战记录汇总（`--mission` 看明细） |
| `verify` | `cmd_verify`（[L219](../penagent/cli.py#L219)） | 证据链完整性校验（失败非零退出） |
| `dsh-sync` | `cmd_dsh_sync`（[L231](../penagent/cli.py#L231)） | 导入宿主 spool 到证据链（`--spool / --chain / --no-state / --replay / --flush-open`） |
| `mcp` | `cmd_mcp`（[L259](../penagent/cli.py#L259)） | 启动 MCP Server（stdio）；`--targets / --authorize / --default-mode / --session-key / --discover-mcp` |
| `scope` | `cmd_scope`（[L285](../penagent/cli.py#L285)） | 会话授权目标管理（`--add / --remove / --clear / --note / --session-key`） |
| `tree` | `cmd_tree`（[L310](../penagent/cli.py#L310)） | 审计层级视图（`--mission / --json`） |
| `gaps` | `cmd_gaps`（[L322](../penagent/cli.py#L322)） | 技能盲区发现（`--llm` 走 LLM 分析） |
| `eval` | main 内联（[L477](../penagent/cli.py#L477)） | 转调 `examples/eval_evolution.py` |

`_make_agent(args, registry=None, memory=None, evidence=None)`（[L23](../penagent/cli.py#L23)）是统一装配点：加载模式 → `build_center(...).build_registry(mode)` → `Memory/EvidenceChain/Policy` → 可选加载 RL 策略（`.pt` 走 PPO，其余走 Q-learning）。

---

## 6. 工具层（三层工具面与统一注册中心）

### 6.1 [tools.py](../penagent/tools.py) — 执行入口与数据结构

| 符号 | 位置 | 说明 |
|---|---|---|
| `FROZEN_ARGS_KEY = "_frozen_args"` | [L31](../penagent/tools.py#L31) | 模式冻结参数在 args 中的保留键（按命令行 token 追加到命令尾部） |
| `ToolSpec` | [L35](../penagent/tools.py#L35) | `name / description / kind(function\|cli\|http) / parameters(JSON Schema 子集) / fn / command(模板，`{args}` 替换) / workdir / timeout / dangerous / positional / arg_flags / sandbox / network`；`to_schema()` |
| `ToolResult` | [L59](../penagent/tools.py#L59) | `tool / ok / output / error / duration_ms`；`to_dict()` |
| `business_error(output)` | [L70](../penagent/tools.py#L70) | 结果语义统一：返回值带非空 `error` 键即判失败——供 `execute` 映射 `ok=False`（R-36） |
| `ToolRegistry(sandbox=None, gate=None)` | [L94](../penagent/tools.py#L94) | **持有沙箱策略与闸门**（执行前裁决发生在 `execute()` 内部） |
| `.register / .get / .schemas / .names` | [L105-L115](../penagent/tools.py#L105-L115) | 注册表基本操作 |
| `.copy(*, gate=None)` | [L117](../penagent/tools.py#L117) | 复制注册表（工具集相同）并可换装闸门——为**一次任务**派生独立护栏，不改共享注册表（避免权限放大） |
| `.execute(name, args, confirm_high_risk=True)` | [L131](../penagent/tools.py#L131) | 顺序：闸门裁决 → 沙箱裁决 → 按 `kind` 执行（`function` 按 `parameters` 过滤入参；`mcp` 原样透传且剥离冻结键；`cli` 走 `_run_cli`）→ **业务失败映射 `ok=False`** |
| `._run_cli(spec, args, wrapper=None)` | [L181](../penagent/tools.py#L181) | 模板替换 + 可执行文件存在性校验（容器执行时由 wrapper 接管）；返回 `stdout[-4000:]` |
| `._cli_args(spec, args)` | [L208](../penagent/tools.py#L208) | 位置参数模式 / `--key`（可由 `arg_flags` 覆盖）/ 布尔开关；冻结串经 `shlex.split` 追加 |

### 6.2 [registry.py](../penagent/registry.py) — 统一注册中心

| 符号 | 位置 | 说明 |
|---|---|---|
| `SOURCE_FUNCTION / SOURCE_CLI / SOURCE_MCP`、`SOURCES` | [L30-L33](../penagent/registry.py#L30-L33) | 三种能力形态 |
| `DEFAULT_MCP_SERVERS_JSON`、`DEFAULT_DISCOVER_BUDGET = 180.0` | [L35-L41](../penagent/registry.py#L35-L41) | 外部 MCP 发现的**全局预算**（秒）；防止最坏耗时等于各 server timeout 之和 |
| `normalize_discover(value)` | [L44](../penagent/registry.py#L44) | `--discover-mcp` 多种写法归一：`None/False/""`=不发现；`True/"*"/"all"`=全部；`"a,b"`=子集 |
| `ToolEntry(name, source, origin, spec, modes, kernel, remote)` | [L70](../penagent/registry.py#L70) | `available_in(mode_id)`、`to_meta()`；`modes` 空 = 全模式；`kernel=False` = 只暴露给 MCP 客户端、不进内核循环 |
| `ToolCenter` | [L98](../penagent/registry.py#L98) | 登记 → 发现 → 按模式构建注册表 |
| `.register_spec(spec, *, source, origin, modes=(), kernel=True, remote="")` | [L108](../penagent/registry.py#L108) | 同名冲突**不静默**：覆盖照旧但记 `notes`（P1-3 去重器） |
| `.register_builtins()` / `.register_server_tools(specs, origin="server")` | [L133](../penagent/registry.py#L133) | 内核内置 / 服务端高层能力（`pentest_*`） |
| `.load_external_cli(path=None)` | [L150](../penagent/registry.py#L150) | 从 `external_tools.json` 登记 CLI 工具（不可用不注册） |
| `.load_cli_config(path, *, origin=None, default_modes=())` | [L161](../penagent/registry.py#L161) | 扩展 schema：`modes` / 参数级 `flag` / 命令里的 `{python}` 展开 |
| `.load_mcp_servers(path=None)` | [L218](../penagent/registry.py#L218) | 只登记声明，不连接；`envcfg.expand_deep` 展开 `${VAR}` |
| `.discover(*, source=None, origin=None, mode_id=None, kernel=None)` | [L237](../penagent/registry.py#L237) | 按来源/模式可用性过滤 |
| `.all_entries()` / `.servers()` / `.summary()` | [L257-L273](../penagent/registry.py#L257-L273) | 不过滤模式的完整清单（诊断用）/ server 列表 / 统计与 notes |
| `.discover_mcp(name=None, probe=probe_server, budget=None)` | [L275](../penagent/registry.py#L275) | 连接外部 server 并登记工具；全局预算夹住单 server timeout，耗尽即跳过并记原因 |
| `._tool_filtered_out(server, tool)` / `._register_mcp_tool(server, tool)` | [L353](../penagent/registry.py#L353) | 工具面白名单（`deny` 优先，`allow` 非空即白名单）+ 远端工具注册（名字规范为 `<server>_<remote>`） |
| `.build_registry(mode=None, *, kernel_only=True, sandbox=None)` | [L393](../penagent/registry.py#L393) | 按模式可用性构建内核注册表，并挂沙箱策略（`egress` 随模式） |
| `.schemas(mode=None, *, kernel_only=False)` | [L417](../penagent/registry.py#L417) | 导出工具 schema（MCP tools/list 来源） |
| `build_center(*, with_builtins=True, with_external_cli=True, with_mcp_servers=True, with_ctf_tools=True, with_adapters=True, discover_mcp=False, discover_budget=DEFAULT_DISCOVER_BUDGET)` | [L438](../penagent/registry.py#L438) | 组装默认注册中心（登记 + 声明；**默认不连接外部 MCP**） |

`_mcp_caller(server, remote)`（[L425](../penagent/registry.py#L425)）是外部 MCP 工具的调用闭包：每次调用建连、用完即杀，不留常驻进程。

### 6.3 三类工具面

**（1）内置 function 工具**（[builtin_tools.py](../penagent/builtin_tools.py) 的 `register_builtins`，[L377](../penagent/builtin_tools.py#L377)）：

| 工具 | 实现 | 说明 |
|---|---|---|
| `port_scan` | [L37](../penagent/builtin_tools.py#L37) | TCP 端口扫描（socket 直连） |
| `http_probe` | [L55](../penagent/builtin_tools.py#L55) | 结论性字段：状态码 / Server / 响应头 / 标题 |
| `dns_lookup` | [L83](../penagent/builtin_tools.py#L83) | DNS 解析 |
| `robots_fetch` | [L92](../penagent/builtin_tools.py#L92) | 抓 robots.txt |
| `http_raw` | [L227](../penagent/builtin_tools.py#L227) | **原始证据**：状态行 + 完整响应头 + 正文片段 + 耗时；支持 `headers/cookie`（CRLF 拒绝、凭据脱敏）、`grep` 服务端定向提取；不跟随重定向（3xx 带 location）、4xx/5xx 按响应返回 |
| `session_http` | [http_session.py L194](../penagent/http_session.py#L194) | 带 cookie jar 的会话态请求；返回 `request_id` 供重放 |
| `replay_request` | [http_session.py L241](../penagent/http_session.py#L241) | 按 request_id 原样重发并比对状态码与正文哈希 → `same_status / same_body / verdict.hint` |
| `report_gen` | [L334](../penagent/builtin_tools.py#L334) | 产出 markdown 或 SARIF 报告，可选落盘 `<data>/reports/`（禁止路径穿越） |

共用的安全原语：`_allow_http_url(url)`（工具体内第二道边界：仅 http(s)、拒绝链路本地/组播/保留段）、`_clean_headers(headers, cookie)`（RFC 7230 tchar、拒绝 CR/LF 注入、值限长 2000、总数限 20、**逐条丢弃并报告**）、`_mask_headers`、`mask_response_headers`（脱敏 `Set-Cookie` 的值）、`_grep_body(text, pattern, max_matches=20, max_lines=10)`、`GREP_SCAN_CAP = 65536`。

**（2）外部 CLI 工具**（`external_tools.json` + [external_tools.py](../penagent/external_tools.py#L17)）：`load_external_tools` 注册前校验可执行文件存在性，缺失即不注册并在 note 里说明。字段含 `command / workdir / timeout / dangerous / positional / parameters（可带 flag） / sandbox / network`。

**（3）CTF 工具链**（[ctf_tools.py](../penagent/ctf_tools.py) + `ctf_tools.json`）：`codec_decode`（[L116](../penagent/ctf_tools.py#L116)）、`codec_chain`（[L127](../penagent/ctf_tools.py#L127)）、`file_type`（[L145](../penagent/ctf_tools.py#L145)）为 stdlib 实现的 function 工具，`modes=("ctf-web","ctf-crypto")`；`rsactf_attack` / `python_solve` 等外部二进制走 `ctf_tools.json` CLI 登记（`python_solve` 声明 `sandbox: docker`）。

**路径口径（R-38）**：`_resolve_path()`（[L59](../penagent/ctf_tools.py#L59)）让宿主侧路径工具与容器视角等价——`/samples/...` 映射到 `sandbox.data_root()`，相对路径未命中再试 data 目录之下；失败信息带已尝试路径 / cwd / `/samples` 映射目标 / 同目录候选（此前只说"文件不存在"，模型因此重复同一个失败调用 57 次、耗尽 60 步预算）。

**（4）适配层**：`rayscan_scan`（[adapters/rayscan.py](../penagent/adapters/rayscan.py#L31)，wvs 库异步扫描，`dangerous=True`）、`pf_nmap_scan / pf_nmap_services / pf_nmap_vuln`（[adapters/packetforge.py](../penagent/adapters/packetforge.py#L32)）；包不可用时**不注册**（LLM 看不到）。

### 6.4 [sandbox.py](../penagent/sandbox.py) — 隔离档位

| 档位 | 被动工具 | 需要隔离的工具（`dangerous` 或声明 `sandbox`） |
|---|---|---|
| `none` | 直接执行 | **拒绝** |
| `local` | 直接执行 | 宿主直跑（仍过白名单与授权档位） |
| `docker` | 直接执行 | 容器内执行；**容器不可用则拒绝，绝不裸跑** |

| 符号 | 位置 | 说明 |
|---|---|---|
| `LEVELS` / `DEFAULT_IMAGE="python:3.12-slim"` / `CONTAINER_WORKDIR="/work"` / `CONTAINER_TOOLS_DIR="/opt/host-tools"` / `CONTAINER_TEMPLATES_DIR="/root/nuclei-templates"` / `CONTAINER_SAMPLES_DIR="/samples"` / `DEFAULT_DATA_ROOT="data"` | [L26-L43](../penagent/sandbox.py#L26-L43) | 档位与容器路径常量（`/samples` = 宿主 data 目录的容器视图） |
| `configure_data_root(path)` / `data_root()` | [L48](../penagent/sandbox.py#L48) / [L59](../penagent/sandbox.py#L59) | 注入 / 读取宿主 data 目录（与 `http_session.configure` 同构；CLI 与 MCP 入口在装配时调用） |
| `tool_needs_isolation(spec)` | [L64](../penagent/sandbox.py#L64) | 声明 `sandbox: docker/container` 或 `dangerous=True` |
| `SandboxDecision(allowed, reason, isolated, wrap)` | [L73](../penagent/sandbox.py#L73) | 裁决结果 |
| `host_data_mounts()` | [L106](../penagent/sandbox.py#L106) | 只读挂载清单：`$PENTEST_TOOLS → /opt/host-tools`、`~/nuclei-templates → /root/nuclei-templates`、**data → `/samples`**（目录不存在则不挂） |
| `containerize_command(command, data_root="")` | [L139](../penagent/sandbox.py#L139) | 宿主路径 → 容器路径重写：宿主解释器 → `python`；`.exe` 二进制 → 工具名；数据根之下 → `/opt/host-tools/...` |
| `DockerRunner(image="", probe_timeout=8.0)` | [L191](../penagent/sandbox.py#L191) | `available()`（探测结果缓存）/ `wrap(command, spec)`（`-v` 宿主侧、`-w /work`、默认 `--network none`）/ `network_mode(spec)` |
| `SandboxPolicy(level="none", runner=None, egress=False)` | [L257](../penagent/sandbox.py#L257) | `availability()` / `decide(spec)`：出网声明在 `egress=False` 时**先拒**；容器不可用时的错误消息**含修复指引** |
| `build_sandbox(level, runner=None, egress=False)` | [L330](../penagent/sandbox.py#L330) | 工厂函数 |

`_slash_norm` / `_basename_no_exe`（[L82-L104](../penagent/sandbox.py#L82-L104)）刻意不用 `os.path`——让 Windows 生产端与 Linux CI 对同一段路径给出同一结论。

### 6.5 [mcp.py](../penagent/mcp.py) — 本内核作为 MCP Server

协议：JSON-RPC 2.0 over stdio（`initialize` / `notifications/initialized` / `tools/list` / `tools/call`），`MCP_VERSION = "2025-06-18"`。

| 符号 | 位置 | 说明 |
|---|---|---|
| `SERVER_TOOLS` | [L33](../penagent/mcp.py#L33) | 服务端高层能力：`pentest_run` / `pentest_set_mode` / `pentest_evidence` / `pentest_skills` / `pentest_missions` / `pentest_reflect`（`kernel=False`，不进内核循环） |
| `PentestMCPServer(data_dir="data", allowed_targets=None, center=None, authorize=False, default_mode="", session_key="")` | [L81](../penagent/mcp.py#L81) | 构造期即校验 `default_mode` 存在性（fail-closed） |
| `._refresh_scope()` | [L138](../penagent/mcp.py#L138) | 每请求前比对会话授权文件变化，变了就重建 Policy/闸门/模式工具面（**不重启生效**） |
| `._agent(authorize=False, mode_id="", on_event=None)` | [L179](../penagent/mcp.py#L179) | 内层 ReAct Agent；模式回落链：调用参数 → 会话模式文件 → 服务端 `--default-mode` |
| `._mode_registry(mode)` | [L224](../penagent/mcp.py#L224) | 按模式构建「可执行工具面」（`entry.modes` + `capability` 两层过滤 + 闸门），按模式缓存；**`tools/list` 与 `tools/call` 共用同一判据** |
| `._tools_schema()` | [L271](../penagent/mcp.py#L271) | 按 MCP 规范导出（`name / description / inputSchema`；`dangerous` → `annotations.destructiveHint`），并按当前模式裁剪 |
| `._maybe_notify_tools_changed()` | [L301](../penagent/mcp.py#L301) | 模式变化时发 `notifications/tools/list_changed`（客户端重取工具面） |
| `.handle_line(line)` / `.serve_stdio()` | [L319](../penagent/mcp.py#L319) | 逐行 JSON-RPC 处理 / stdio 主循环（强制 UTF-8） |
| `._handle_call(msg_id, params)` | [L384](../penagent/mcp.py#L384) | 高层能力分支 + 底层工具分支；异常与失败走 `isError=true` 结构化结果 |
| `._result(msg_id, content, is_error=False)` | [L449](../penagent/mcp.py#L449) | 按规范包成 `content` 块数组 |
| `_progress_token(params)` / `._progress_emitter(token)` | [L66](../penagent/mcp.py#L66) / [L363](../penagent/mcp.py#L363) | 进度令牌解析与 `notifications/progress` 事件流 |

### 6.6 [mcp_client.py](../penagent/mcp_client.py) — 外部 MCP server 客户端

| 符号 | 位置 | 说明 |
|---|---|---|
| `PROTOCOL_VERSION` / `CLIENT_INFO` / `ALLOWED_SCHEMES` | [L37-L39](../penagent/mcp_client.py#L37-L39) | 协议与地址边界常量 |
| `MCPClientError(RuntimeError)` | [L42](../penagent/mcp_client.py#L42) | 不可达 / 协议出错 |
| `validate_http_url(url)` | [L46](../penagent/mcp_client.py#L46) | 仅 http/https 且必须带主机名（**不阻断环回/私网**——本地 MCP server 本就在环回） |
| `MCPServerSpec` | [L69](../penagent/mcp_client.py#L69) | `name / transport(stdio\|http) / command / url / workdir / pythonpath / timeout / description / modes / dangerous / tool_overrides / tool_filter`；`from_dict`、`availability()` |
| `MCPClient(spec)` | [L150](../penagent/mcp_client.py#L150) | 会话式：`connect()`（initialize + initialized 通知）/ `close()` / `list_tools()` / `call_tool(name, arguments)`；stdio 走 `_spawn/_pump_stdout/_pump_stderr/_read_response/_write`，http 走 `_post`（兼容 JSON 与 SSE，带 `Mcp-Session-Id`，**拒绝跟随重定向**） |
| `probe_server(spec) -> (tools, reason)` | [L391](../penagent/mcp_client.py#L391) | 探测一个 server；不可用返回空列表 + 原因（注册中心据此「不注册」） |

**两条实测教训**（写进文件头）：① 子进程 stdout EOF 时放哨兵立即失败，不等满 timeout（否则 Docker 不可用时 6 个容器 server 会拖住内核启动约 23 分钟）；② stderr 必须有人读，否则子进程写满 64KB 管道即死锁。

---

## 7. 宿主层：DSH preset 与 Web 控制台

### 7.1 DSH 三层分工（实测结论，勿凭直觉改）

| 挂载点 | 作用域 | 本项目把它用在哪 | 实现位置 |
|---|---|---|---|
| `tools/pre-execute`、`tools.restrict` | **按作用域派发**（host 平面收不到 preset 内的工具调用） | 目标动作裁决、循环监督 | **preset 内**：[proteus-tools-policy.mjs](../dsh/.agent-presets/_shared/proteus-tools-policy.mjs)、[proteus-supervisor.mjs](../dsh/.agent-presets/_shared/proteus-supervisor.mjs) |
| `session/event` | **全局事件** | 会话审计（每次工具调用落 spool） | **host 平面 bundle**：[proteus-bridge](../dsh/proteus-bridge/index.mjs) |
| 工具能力本体 | — | MCP server | `python -m penagent mcp`（与 DSH 版本解耦） |

### 7.2 preset 模板与渲染

[dsh/.agent-presets/_shared/agent.cordis.template.yml](../dsh/.agent-presets/_shared/agent.cordis.template.yml) 是**模板**（基座为官方 standard preset 的 fork），由 `tools/dsh_install.py` 渲染成三个 preset——**改模板就是改三个 preset**。

| 占位符 | 取值来源 | pentest | ctf-web | ctf-crypto |
|---|---|---|---|---|
| `{{PRESET_ID}}` | `PRESETS` 键 | `proteus-pentest` | `proteus-ctf-web` | `proteus-ctf-crypto` |
| `{{PRESET_LABEL}}` | `PRESETS[...]["label"]` | 渗透场景 | CTF Web 场景 | CTF Crypto 场景 |
| `{{DEFAULT_MODE}}` | `PRESETS[...]["mode"]` | `pentest-standard` | `ctf-web` | `ctf-crypto` |
| `{{PERSONA_PROMPT}}` | `PRESETS[...]["persona"]` | `dsh-persona.md` | `dsh-persona-ctf.md` | `dsh-persona-ctf.md` |
| `{{SESSION_KEY}}` | `PRESETS[...]["session_key"]` | `pentest` | `ctf-web` | `ctf-crypto` |

`SESSION_KEY` 是**会话状态隔离键**：三个 preset 共用一个 `data/`，模式文件、授权文件、技能导出目录、spool 归属全部按它分文件，避免「在一个 preset 里授权，另一个 preset 自动生效」。

**模板中的 Proteus 专属行（5 处）**：

| 行 id | 模块 | 关键配置 |
|---|---|---|
| `persona` | `./proteus-persona.mjs` | 读 `prompts/{{PERSONA_PROMPT}}` 注册成 `deployment:persona-prefix` 分区（遮蔽部署默认人格，提示词以仓库文件为唯一来源）；`suffix` 说明本会话 preset 与默认模式 |
| `proteus-tools-policy` | `./proteus-tools-policy.mjs` | `role: policy`、`mode: ask`、`kernelGuard: deny`、`targets: [127.0.0.1, localhost]`、`shellTools: [pwsh, bash]`、`spoolPath` / `scopePath` / `modePath`（按 `{{SESSION_KEY}}` 分文件） |
| `proteus-supervisor` | `./proteus-supervisor.mjs` | `sameToolLimit: 5`、`totalLimit: 30`、`escalate: ask`、同一 `spoolPath` |
| `proteus-commands` | `./proteus-commands.mjs` | `sessionKey: '{{SESSION_KEY}}'` |
| `mcp-proteus` | `@deepseek-ai/dsh-mcp-client` | `transport: stdio`、`serverName: proteus`（工具在会话里表现为 `mcp__proteus__<tool>`）、`command: ${PENTEST_PY312}/python.exe`、`args: -m penagent mcp --data data --targets 127.0.0.1,localhost --authorize --default-mode {{DEFAULT_MODE}} --session-key {{SESSION_KEY}} --discover-mcp`、`cwd: ${PENTEST_WS}/proteus-agent`、`env` 透传 LLM 三键、`toolCallTimeoutMs: 600000`、`failOnStartupError: false` |

其余行（`tool-bash` / `tool-pwsh` / `tool-fs` / `tool-fs-search` / `tool-jobs` / `skill-filesystem` / `tool-skill` / `command-goal` / `tool-goal` / `planning` / `compaction` / `delegation` / `tool-ask-user` / `tool-todo` / `tool-web` / `present` 等）逐字沿用基座；`skill-filesystem.customSkillDirs` 指向 `data/dsh-skills/{{SESSION_KEY}}`（内核经验库导出目录）。

### 7.3 共享插件模块（`dsh/.agent-presets/_shared/`）

| 文件 | 导出 | 职责与关键机制 |
|---|---|---|
| [proteus-persona.mjs](../dsh/.agent-presets/_shared/proteus-persona.mjs) | `name` / `inject=['systemPrompt']` / `apply(ctx, config)` | 读人格文件 → `systemPrompt.section({name: 'deployment:persona-prefix', order, text})`；读不到文件即抛错（挂载失败好过空人格静默启动） |
| [proteus-tools-policy.mjs](../dsh/.agent-presets/_shared/proteus-tools-policy.mjs) | `name` / `inject=[]` / `apply(ctx, config)` | **一份实现两个挂载点**，由 `role` 分工：`audit`（订阅 `session/event` → 写 spool）、`policy`（订阅 `tools/pre-execute` → 裁决）、`both`（缺省）。裁决范围仅「对目标发请求的宿主 shell 命令」（`NETWORK_VERBS` + URL/IP/`--host` 提取）；`mcp__proteus__*` 一律放行；**授权文件改写一律拒绝**（自我授权防线）；`kernelGuard` 在内核工具缺位时 fail-closed；裁决结果与 `kernel` 状态一起写 spool（`kind: policy`） |
| [proteus-supervisor.mjs](../dsh/.agent-presets/_shared/proteus-supervisor.mjs) | `name` / `inject=[]` / `apply(ctx, config)` | 宿主侧循环检测：同工具+同参数（键序无关指纹）重复到 `sameToolLimit` → `deny`（理由含"换思路"提示），再触发一次升级为 `ask`；会话总量超 `totalLimit` 也拦；留痕 `kind: supervisor`；会话 id 取不到按 `unknown` 计 |
| [proteus-commands.mjs](../dsh/.agent-presets/_shared/proteus-commands.mjs) | `name` / `inject=['commands']` / `apply(ctx, config)` | 注册 6 个人机命令（见下表）；模式合法性以 `modes/*.yaml` 文件名称为单一事实来源；写操作一律 spawn 内核 CLI（单一实现） |

**人机命令清单**：

| 命令 | 处理函数 | 行为 |
|---|---|---|
| `/proteus-mode [<id>]` | `handleMode`（[L71](../dsh/.agent-presets/_shared/proteus-commands.mjs#L71)） | 查询/设置会话默认模式 → 写 `data/session-mode-<key>.json`（内核逐次读取，无需重启） |
| `/proteus-scope [add\|remove\|clear ...]` | `handleScope`（[L172](../dsh/.agent-presets/_shared/proteus-commands.mjs#L172)） | 会话授权目标（**只有人能执行**）；写操作走 `python -m penagent scope` |
| `/proteus-evidence [<mission>]` | `handleEvidence`（[L109](../dsh/.agent-presets/_shared/proteus-commands.mjs#L109)） | spawn `python -m penagent evidence` |
| `/proteus-skills [<namespace>]` | `handleSkills`（[L130](../dsh/.agent-presets/_shared/proteus-commands.mjs#L130)） | spawn `python -m penagent skills --export --out data/dsh-skills/<key>` |
| `/proteus-tree [<mission>]` | `handleTree`（[L217](../dsh/.agent-presets/_shared/proteus-commands.mjs#L217)） | spawn `python -m penagent tree`（Task→Action→Artifact） |
| `/proteus-audit` | `handleAudit`（[L238](../dsh/.agent-presets/_shared/proteus-commands.mjs#L238)） | 纯 Node fs 读取：spool 事件数/最近 10 条、`dsh-sync` 状态、`dsh-chain.jsonl` 规模 |

### 7.4 host 平面审计桥

[dsh/proteus-bridge/](../dsh/proteus-bridge/index.mjs) 是 host 平面 bundle，`index.mjs` 只做**薄再导出**（指向 `_shared/proteus-tools-policy.mjs`，实现只有一份），`cordis.patch.yml` 以 `role: audit` 插入一行。`package.json` 声明 `dsh.bundle.patch`。

- **为什么 preset 目录不能用链接**：DSH 发现机制不跟随 reparse point，链接会让 preset 从选择器里静默消失。
- **为什么 bundle 必须用官方 `link:` 依赖**：bundle 行可按包名加载，且因 `link:` 指向本仓库，可以相对导入 `_shared/` 里的那份实现。
- 事件字段：`ts / session / preset / kind(call\|result\|policy\|supervisor) / turn / step / callId / tool / args / output / isError / error`；`args`、`output` 各截断到 4000 字符；归属未知（`preset: ''`）**不丢记录**。

### 7.5 [dsh_install.py](../tools/dsh_install.py) — 同步与校验器

| 符号 | 位置 | 说明 |
|---|---|---|
| `SRC_ROOT` / `SHARED` / `TEMPLATE` / `SHARED_FILES` / `PATCH` / `BRIDGE_SRC` / `REQUIRED_FILES` | [L48-L57](../tools/dsh_install.py#L48-L57) | 源与目标常量 |
| `PRESETS` | [L63](../tools/dsh_install.py#L63) | 三个 preset 的渲染取值表 |
| `render_composition(preset_id)` | [L85](../tools/dsh_install.py#L85) | 纯字符串替换五个占位符（`!!js` 行原样保留） |
| `expected_files(preset_id)` / `drift(dst, preset_id="")` | [L105](../tools/dsh_install.py#L105) / [L153](../tools/dsh_install.py#L153) | 期望文件集与**漂移校验**（安装副本过期 = 跑旧代码而无提示） |
| `verify_preset` / `verify_patch` / `verify_gate_consistency[_text]` / `check_bundle` / `check_bridge_entry` / `roster_check` | [L205-L409](../tools/dsh_install.py#L205-L409) | 逐项校验：preset 完整性、patch 行、闸门一致性、bundle 接线、roster 健康（**broken 的 preset 不进选择器且零提示**） |
| `live_check(profile, dirs)` / `bridge_live_check(spool)` | [L581](../tools/dsh_install.py#L581) / [L756](../tools/dsh_install.py#L756) | 运行态检查：进程加载的模块与审计桥代码是否为当前版本 |
| `sync_preset(home, preset_id)` / `_backup_previous(...)` / `migrate_legacy(home)` / `install(home)` | [L819-L891](../tools/dsh_install.py#L819-L891) | 复制 + 启动前同步 + 备份保留（`KEEP_BACKUPS = 3`） |
| `running_dsh` / `terminate_dsh` / `port_in_use` / `wait_port_free` / `wait_gone` | [L449-L661](../tools/dsh_install.py#L449-L661) | 关闭旧实例（否则新实例以 `EADDRINUSE 127.0.0.1:4080` 失败） |
| `workspace_root()` / `_env_file_value(key)` / `verify_launcher(path)` / `launch(profile, dst, port=4080)` | [L662-L755](../tools/dsh_install.py#L662-L755) | 工作区解析（`PENTEST_WS` 或 `.env`）、启动器行尾校验、一键启动 |
| `main(argv)` | [L891](../tools/dsh_install.py#L891) | CLI：`--home / --profile / --check / --no-roster / --spool / --no-live / --port / --launch / --restart / --ask / --no-bundle-check` |

[dsh/start-proteus.cmd](../dsh/start-proteus.cmd) 只是薄启动器（**必须保持 CRLF 行尾**，否则 cmd.exe 会把 `rem` 后的文本与下一行拼成一条命令执行）；真实逻辑全在 `dsh_install.py --launch`。

### 7.6 [web/server.py](../web/server.py) — Web 控制台

零新增依赖（`http.server` + `ThreadingHTTPServer`）。

| 符号 | 位置 | 说明 |
|---|---|---|
| `ConsoleService(data_dir, repo_root)` | [L45](../web/server.py#L45) | 纯逻辑服务层（可单测）：加载全部模式（跳过 `base`） |
| `.modes()` / `.suggest(text)` | [L58](../web/server.py#L58) / [L96](../web/server.py#L96) | 模式清单（含 capability/permission/budget/verifier 全量字段）/ 关键词触发推荐（命中数降序） |
| `.dispatch(mode_id, target, objective, *, driver="scripted", challenge="", authorize=True)` | [L114](../web/server.py#L114) | 起后台线程跑任务，返回运行态 key |
| `._run_cli(...)` | [L151](../web/server.py#L151) | `penagent` 驱动：子进程 `python -m penagent run --mode ...` |
| `._run_scripted(...)` | [L173](../web/server.py#L173) | `scripted` 驱动：进程内构造 `PenAgent` 并 patch `chat_json` 为脚本决策——**真工具、真证据链、真判定器**，只有「模型选哪个工具」由脚本扮演 |
| `.stream_events(mode_id, mission_id, *, poll=0.4, timeout=180.0)` | [L251](../web/server.py#L251) | 增量读作战记录步骤，产出 `waiting / step / verdict / timeout` 事件（flag 语料与判定器同源） |
| `.evidence_view(mode_id, mission_id="")` | [L298](../web/server.py#L298) | 链完整性 + 最近 80 条记录 + 拦截步骤 + 最近结论 |
| `ConsoleHandler` | [L327](../web/server.py#L327) | 薄 HTTP 适配：路由 / JSON / SSE / 静态文件（含越界路径防护） |
| `main(argv)` | [L449](../web/server.py#L449) | `--port 8770`、`--host 127.0.0.1`、`--data <repo>/data` |

**HTTP 路由表**：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/modes` | 模式清单 |
| GET | `/api/missions/<mode>` | 该模式分区的作战记录列表 |
| GET | `/api/mission/<mode>/<mission>` | 单条作战记录 |
| GET | `/api/evidence/<mode>[/<mission>]` | 证据链视图 |
| GET | `/api/state/<key>` | 任务运行态 |
| GET | `/api/stream/<mission>?mode=<id>` | SSE 步骤流（`verdict` / `timeout` 后关闭） |
| POST | `/api/suggest` | 关键词 → 推荐模式 |
| POST | `/api/tasks` | 下发任务（202 Accepted 返回运行态） |
| GET | 其他路径 | 静态文件（`web/static/`，含路径越界防护） |

前端（[index.html](../web/static/index.html) + `app.js` + `app.css`）三视图：模式选择与关键词触发、任务下发与实时步骤流、证据链校验。

---

## 8. 依赖关系全景

### 8.1 内核内部依赖（import 关系）

```
                         ┌──────────────┐
                         │   agent.py   │  ← 顶层编排（唯一持有 ReAct 循环）
                         └──┬───┬───┬───┘
              ┌─────────────┘   │   └──────────────┬──────────────┐
              ▼                 ▼                  ▼              ▼
      evidence.py          llm.py            memory.py      verifier.py
              ▲                 ▲                  ▲              ▲
              │                 │                  │              │
        ┌─────┴─────┐     ┌─────┴─────┐      ┌─────┴─────┐  ┌─────┴──────┐
        │  report.py│     │ reflect.py│      │skill_seeds│  │   rl / ppo │
        │dsh_bridge │     │  gaps.py  │      │skill_export│ └────────────┘
        └───────────┘     └───────────┘      └───────────┘
              ▲
              │
        ┌─────┴───────────────────────────────────────────┐
        │  tools.py（ToolSpec / ToolRegistry）            │  ← 执行入口
        └──┬───────────────┬──────────────────┬──────────┘
           ▼               ▼                  ▼
    policy_gate.py    sandbox.py        registry.py（ToolCenter / build_center）
                                           │  ├── builtin_tools.py / http_session.py
                                           │  ├── external_tools.py + .json
                                           │  ├── ctf_tools.py + .json
                                           │  ├── mcp_client.py（外部 server）
                                           │  └── adapters/{rayscan,packetforge}.py
                                           ▼
                                    modes.py（ModeProfile，依赖 tools.ToolRegistry）
                                           ▲
        cli.py / mcp.py / web.server.py ────┘  ← 三个入口都经 build_center + ModeProfile
                    ▲
                    └── envcfg.py（.env 与 ${VAR}：被 llm / registry / external_tools /
                                     adapters / conftest 使用）
```

**层级规则与循环导入规避**：

- `agent.py` 之外的模块**不 import `agent.py`**；`policy_gate.py` 用 `_PolicyLike` Protocol 声明所需方法（只需 `check` / `level_for`），避免与 `agent.py` 循环导入。
- `tools.py` 不 import `sandbox.py` / `policy_gate.py`（只用 `Optional` 前向类型）；`agent.py`、`registry.py` 在**函数内**延迟 import `sandbox` / `policy_gate`，打破环。
- `modes.py` 只依赖 `tools.ToolRegistry`（构建过滤后的注册表）。
- `mcp.py` 依赖 `agent` / `evidence` / `llm` / `memory` / `policy_gate` / `reflect` / `registry` / `scope` / `tools`——它是宿主侧装配层，不是内核被依赖方。

### 8.2 外部依赖

| 依赖 | 定位 | 缺失时的行为 |
|---|---|---|
| PyYAML | 必需（解析 `modes/*.yaml`） | 模式层不可用 |
| pytest | 开发/CI | — |
| torch（CPU） | **可选**（`rl.py` / `ppo.py` 的 PPO 分支） | 相关用例 `importorskip` 跳过，其余功能不受影响；刻意不进 `requirements.txt` 安装列表 |
| 07 靶场 `warfare` 包 | 外部（评测脚本 `eval_evolution*.py` / `eval_closed_loop.py` / `benchmark --suite g07`） | `conftest.py` 按 `PENTEST_G07_ROOT` → 相邻布局解析；找不到则对应用例 skip，不崩溃 |
| 本地工具库（约 70 个二进制） | 外部（`${PENTEST_TOOLS}`） | 「不可用不注册」，LLM 看不到该工具 |
| RayScan / PacketForge / Chameleon / seckb 等 | 外部项目（`${PENTEST_WS}` 下） | 适配层/ MCP 声明不注册，并记 note |
| Docker（或 WSL2 后端） | 环境（`sandbox: docker` 档位） | **拒绝执行需要隔离的工具**，不静默降级 |
| LLM 端点（OpenAI 兼容） | 环境（`PENTEST_LLM_*`） | 未配置 API key 时 `chat()` 直接抛 `LLMError`；Web 的 `scripted` 驱动可离线演示 |
| Node.js | 仅 DSH 宿主层与 `tests/test_proteus_commands.py`、`test_tools_policy.py`、`test_supervisor.py`、`test_dsh_bridge.py`（用 `node --input-type=module` 加载 .mjs） | 内核本身不依赖 Node |
| deepseek-harness | 宿主（方案 D） | CLI / Web / MCP 三条入口照常可用 |

---

## 9. 运行方式

### 9.1 环境准备

1. 复制 `.env.example` 为 `.env`，填入 LLM 三键与本机路径（不填则对应外部工具自动降级跳过）：

| 变量 | 含义 | 消费方 |
|---|---|---|
| `PENTEST_WS` | 工作区根（本仓库与其他项目所在目录） | `external_tools.json` / `mcp_servers.json` / adapters / DSH preset |
| `PENTEST_TOOLS` | 本地工具库根（httpx / nuclei 等二进制） | `external_tools.json` / 沙箱只读挂载 |
| `PENTEST_PY312` | Python 3.12 解释器路径 | DSH preset（容器外 CLI 调用） |
| `PENTEST_G07_ROOT` | 07 靶场根（含 `warfare` 包） | `conftest.py` / 评测脚本 |
| `PENTEST_DOCKER_IMAGE` | 沙箱镜像（缺省 `python:3.12-slim`） | `penagent/sandbox.py` |
| `PENTEST_LLM_BASE_URL` / `_API_KEY` / `_MODEL` | OpenAI 兼容端点 | `penagent/llm.py` |
| `PENTEST_LLM_MODEL_CHEAP` / `_STRONG` | `budget.model_tier` 档位模型（可选） | `_tier_model()` |
| `PENTEST_WSL_DISTRO` / `PENTEST_R2MCP_BIN` | radare2 MCP（经 WSL，暂未接线） | — |

2. `pip install -r requirements.txt`（可选：`pip install torch -i https://mirrors.aliyun.com/pypi/simple/` 启用 RL 链路）。
3. 可选：`docker build -f docker/Dockerfile.sandbox -t proteus-sandbox:latest docker/` 后设 `PENTEST_DOCKER_IMAGE=proteus-sandbox:latest`。

### 9.2 入口一 · CLI（日常主用）

```bash
# 起一个授权本地靶子
python examples/target.py --port 8080

# 渗透模式侦察任务（真 LLM 决策 + 证据链 + 反幻觉）
python -m penagent run --mode pentest-standard --target http://127.0.0.1:8080 \
    --objective "识别开放端口、Web 技术栈、敏感路径与信息泄漏"

# CTF 模式解题（题面由 examples/eval_ctf_solve.py 生成到 data/eval-ctf/）
python -m penagent run --mode ctf-crypto --target data/eval-ctf/encoding-chain.txt \
    --objective "解出 flag"

# 任务后复盘 → 技能沉淀
python -m penagent reflect <mission_id>

# 预置技能种子（幂等，写进模式记忆分区）
python -m penagent skills --seed --mode pentest-standard

# 查询与校验
python -m penagent skills && python -m penagent missions
python -m penagent verify && python -m penagent gaps
python -m penagent tree --mission <mission_id>
python -m penagent agents --mode ctf-web

# 会话授权（人工入口）
python -m penagent scope --add 10.0.0.5 --note "内部授权"
```

### 9.3 入口二 · Web 控制台

```bash
python web/server.py            # 默认 http://127.0.0.1:8770
python web/server.py --port 9000 --data data
```

界面驱动可选 `scripted`（离线，无需 API key）或 `penagent`（真实内核子进程）。

### 9.4 入口三 · MCP Server（供 Claude Code / Codex / OpenCode 等客户端）

```bash
python -m penagent mcp --targets 127.0.0.1 --default-mode pentest-standard
python -m penagent mcp --discover-mcp            # 连接全部声明的外部 MCP server
python -m penagent mcp --discover-mcp seckb,rayscan
```

工具在客户端侧表现为 `pentest_run / pentest_evidence / ...` 以及各底层工具；模式切换会触发 `notifications/tools/list_changed`。

### 9.5 入口四 · DSH 宿主

```bash
python tools/dsh_install.py                       # 复制 + 同步 + 漂移校验
python tools/dsh_install.py --check               # 只检查（有漂移即非零退出）
python tools/dsh_install.py --launch              # 启动器用：同步 + 关旧实例 + 启动
dsh/start-proteus.cmd                             # 双击式一键启动（内部转调 --launch）
dsh plugin --profile web add <REPO>/dsh/proteus-bridge   # 安装 host 平面审计桥后需重启 DSH
```

安装后 `dsh` 会话里：三个 preset（Proteus 渗透 / CTF-Web / CTF-Crypto）选中即用，工具以 `mcp__proteus__*` 出现，命令见 7.3 节。

### 9.6 内核会话审计桥

```bash
python -m penagent dsh-sync --data data                      # 增量导入 spool → dsh-chain.jsonl
python -m penagent dsh-sync --data data --flush-open          # 会话结束冲刷未配对调用
python -m penagent dsh-sync --data data --replay --chain <path>  # 换链重建
```

### 9.7 测试

```bash
pytest                                  # 全量
pytest tests/test_policy_gate.py -q     # 单文件
python tools/scrub_paths.py --check     # 本机路径残留校验（有残留即非零退出）
```

`conftest.py` 会在会话开始时装载 `.env`、解析 07 靶场并注入 `sys.path` / `PYTHONPATH`；找不到靶场时仅跳过 4 个依赖 `warfare` 的用例（`G07_DEPENDENT_NODEIDS`）。另有 `host_direct_sandbox` fixture：把走内核构造路径的注册表钉成 `local` 档，让解题链路仍被真跑覆盖（与 `test_sandbox.py` 里「无容器必须拒绝」的用例互补）。

### 9.8 能力评测

```bash
python examples/benchmark.py --suite all              # 全部套件（不含 agent-lab）
python examples/benchmark.py --suite ctf              # CTF 33 题（纯离线，约 5 秒）
python examples/benchmark.py --suite pentest          # 本地演示靶侦察
python examples/benchmark.py --suite lab              # 真实靶场基线（DVWA / Juice Shop / sw-secure-lab）
python examples/benchmark.py --suite agent-lab        # agent 自主侦察真实靶场（真 LLM，分钟级，须显式点名）
python examples/benchmark.py --suite g07              # 07 靶场仿真（需 warfare）
python examples/benchmark.py --suite dsh-session      # 判定 DSH 宿主会话（离线）
python examples/benchmark.py --compare data/benchmark/baseline.json
```

CI（`.github/workflows/ci.yml`）在 pytest 之后跑 `python examples/benchmark.py --suite ctf` 作为**能力闸门**。

---

## 10. 数据与产物

`data/` 已 gitignore，是全部运行时状态的落点：

| 路径 | 生产者 | 内容 / schema 要点 |
|---|---|---|
| `data/chain.jsonl` | `EvidenceChain` | 扁平链式哈希记录：`{seq, kind, content, timestamp, prev_hash, hash}`；`content` 带 `mission` / `step` 归属 |
| `data/missions/<ns>/<id8>.json` | `Memory` | `{id, target, objective, started_at, finished_at, steps[], reflection, outcome, evidence_refs[]}` |
| `data/skills/<ns>/<id8>.json` | `Memory` | `Skill` 全字段（含 `success_rate / successes / attempts / exposure`） |
| `data/session-mode[-<key>].json` | `/proteus-mode`、`pentest_set_mode` | `{mode, set_at}` |
| `data/session-scope[-<key>].json` | `/proteus-scope`、`penagent scope` | `{targets[], updated_at, note}` |
| `data/dsh-events.jsonl` | DSH 桥 / 监督层 | 宿主会话事件（`kind: call\|result\|policy\|supervisor`） |
| `data/dsh-chain.jsonl` | `dsh-sync` | 宿主会话证据链（默认与内核任务链**分开**，避免混进 mission 窗口与 verify 口径） |
| `data/dsh-spool.state.json` | `dsh-sync` | 增量偏移 + 未配对调用 |
| `data/http-sessions/<session>.json` | `http_session` | cookie jar（明文）+ 最近 50 条请求日志（`request_id / url / method / oracle(正文哈希) / status`） |
| `data/dsh-skills/<key>/*.md` | `skills --export` | DSH 扁平技能（YAML frontmatter），供 preset `customSkillDirs` |
| `data/reports/` | `report_gen` | markdown / SARIF 报告 |
| `data/benchmark/` | `examples/benchmark.py` | 评分卡 JSON（`--out`，缺省 `run.json`）与各套件中间产物 |
| `data/eval-ctf/` | `examples/eval_ctf_solve.py` | 33 道声明式离线题面 |
| `data/rl/policy.json` | `examples/train_policy.py` | Q 表（Q-learning 策略） |

---

## 11. 安全机制与不可违反的不变量

### 11.1 纵深防御（每一道都在「工具执行前」生效）

| 层 | 机制 | 位置 | 拒绝后的可见性 |
|---|---|---|---|
| 工具面 | `capability.allow/deny` 裁剪注册表（禁用的工具不进 schema 也执行不了） | `ModeProfile.filtered_registry` | 决策里给准确原因（`denial_reason`），并留 `blocked` 证据 |
| 权限档位 | `hard_deny` / `require_confirm`(ask) / `auto_approve` / `default` | `Permission.level_for` → `Policy.check` | 拦截理由 + 证据链留痕 |
| 闸门 | 协议白名单（仅 http/https）、目标白名单、高危授权 | `PolicyGate.check` | `GateDecision` 带 `rule` / `level`（供审计与审批展示） |
| 沙箱 | `none/local/docker`；容器不可用**拒绝而非裸跑**；`--network none` 默认断网 | `SandboxPolicy.decide` | 错误消息含**可操作修复指引** |
| 出网 | `scope.network_egress=false` 时闸门 + 沙箱**双层**拒绝声明 `network=True` 的工具 | `Policy.check` + `SandboxPolicy.decide` | — |
| 工具体 | URL 边界（仅 http(s)、拒绝链路本地 `169.254.0.0/16` / 组播 / 保留段）；请求头 CRLF 拒绝；凭据脱敏 | `_allow_http_url` / `_clean_headers` / `_mask_headers` / `mask_response_headers` | `header_problems` 逐条回传 |
| 授权 | 目标白名单硬校验；会话授权「只有人能写」；**模型不能自我授权**；宿主 shell 改写授权文件一律拒绝 | `scope.py` / `Policy.check` / `proteus-tools-policy.mjs` | 拒绝理由带授权指引 |
| 审计 | 全动作链式哈希留痕；宿主旁路也留痕（`session/event` → spool → `dsh-sync`） | `evidence.py` / `dsh_bridge.py` | `verify()` 报 `tampered` / `broken_links` |
| 循环防护 | 内核步数/时长预算（超限换策略收口）+ 宿主侧监督层（同调用重复 5 次拦、会话 30 次拦） | `PenAgent.run` / `proteus-supervisor.mjs` | 监督理由是「换思路」的具体建议 |

### 11.2 不可违反的不变量（改动前必读）

1. **禁用即拒绝**：模式约束必须在工具体被调用之前生效；只写提示词不算实现。
2. **反幻觉底线**：结论引用不存在的证据 seq 一律判失败且不给重试——这是内核不变量，不是模式可调项。
3. **白名单不可绕过**：越界目标一律拒绝；`authorize` 只来自持有闸门的一方（操作员），**调用参数里的 `authorize` 不生效**。
4. **内核不依赖宿主**：`penagent/` 不 import DSH / Claude Code 专属能力；宿主只通过 MCP 或子进程调用内核。
5. **链式哈希只实现一份**：插件只落原始事件，哈希与链接由 `evidence.py` 完成。
6. **不静默降级**：容器不可用、工具缺失、MCP 不可达……一律「拒绝 / 不注册 + 明确原因」，绝不悄悄回退到更弱的路径。
7. **入库零本机路径**：配置写 `${VAR}`；`tools/scrub_paths.py` 就地清洗、`tests/test_path_hygiene.py` 机制性把关。
8. **不引入重型依赖**：能用 stdlib / dataclass 就不引 Pydantic / LangChain。

---

## 12. 测试体系与能力评测

### 12.1 用例文件清单（31 个）

| 用例文件 | 测什么 |
|---|---|
| [test_core.py](../tests/test_core.py) | 证据链 / 记忆 / 工具注册表 / 内置工具 |
| [test_agent.py](../tests/test_agent.py) | 决策循环：安全护栏 / 反幻觉 / 决策流转（mock LLM） |
| [test_modes.py](../tests/test_modes.py) | 模式加载 / inherits 深合并 / 校验失败 / 能力过滤机制性生效 + **工具真名核对** |
| [test_policy_mode.py](../tests/test_policy_mode.py) | 模式驱动的执行前裁决（禁用即拒绝） |
| [test_policy_gate.py](../tests/test_policy_gate.py) | 闸门：协议白名单 / 目标白名单 / 高危授权 / 参数授权不生效 |
| [test_budget_scope.py](../tests/test_budget_scope.py) | `budget` / `scope` 字段机制性生效（出网闸门、档位模型、时长收口） |
| [test_verifier.py](../tests/test_verifier.py) | 可插拔判定器（含反幻觉不可重试） |
| [test_memory_namespace.py](../tests/test_memory_namespace.py) | 记忆分区与步数预算 |
| [test_m2.py](../tests/test_m2.py) / [test_m3.py](../tests/test_m3.py) / [test_m4.py](../tests/test_m4.py) | M2 记忆闭环 / M3 成功率回写与进化评测 / M4 相关行为 |
| [test_skill_seeds.py](../tests/test_skill_seeds.py) | 种子能入库、能匹配、能进提示词、不覆盖学习结果 |
| [test_rl.py](../tests/test_rl.py) / [test_rl_inject.py](../tests/test_rl_inject.py) / [test_ppo.py](../tests/test_ppo.py) / [test_closed_loop.py](../tests/test_closed_loop.py) | Q-learning / 策略注入 / PPO 网络与持久化 / 闭环评测 |
| [test_registry.py](../tests/test_registry.py) | 统一注册中心：来源 / 模式可用性 / 同名冲突 / 外部 MCP 登记与过滤 |
| [test_mcp.py](../tests/test_mcp.py) | MCP Server 协议、工具面裁剪、`listChanged`、底层工具失败语义 |
| [test_ctf_solve.py](../tests/test_ctf_solve.py) | CTF 工具链离线端到端解出 flag |
| [test_scope.py](../tests/test_scope.py) | 会话授权三层：读 / 写 / 内核不写 |
| [test_sandbox.py](../tests/test_sandbox.py) | 三档行为与降级路径（含"容器不可用必须拒绝且不裸跑"、消息含修复指引） |
| [test_builtin_schemes.py](../tests/test_builtin_schemes.py) | 工具体内 URL 边界（`file://` 与云元数据拒绝） |
| [test_http_session.py](../tests/test_http_session.py) | 会话态 HTTP：cookie 吸收、重放比对、凭据不回显 |
| [test_llm_client.py](../tests/test_llm_client.py) | 会话头、端点协议白名单、读超时重试（全部打桩本地 HTTP） |
| [test_mission_tree.py](../tests/test_mission_tree.py) | Task→Action→Artifact 层级视图与两条兜底边界 |
| [test_web_console.py](../tests/test_web_console.py) | 控制台：模式/关键词、任务下发与步骤流、证据链视图 |
| [test_benchmark.py](../tests/test_benchmark.py) | 评分卡聚合、序列化往返、`--compare` 方向、skipped 语义 |
| [test_dsh_bridge.py](../tests/test_dsh_bridge.py) | DSH spool → 证据链（配对 / 不重复入链 / 形状一致） |
| [test_dsh_install.py](../tests/test_dsh_install.py) | 同步器每条校验可独立触发（防 preset 静默消失、副本过期） |
| [test_proteus_commands.py](../tests/test_proteus_commands.py) | `proteus-commands.mjs` 六个命令的端到端 handler |
| [test_tools_policy.py](../tests/test_tools_policy.py) | `proteus-tools-policy.mjs` 裁决行（含模式驱动的档位） |
| [test_supervisor.py](../tests/test_supervisor.py) | `proteus-supervisor.mjs` 循环检测与升级 |
| [test_path_hygiene.py](../tests/test_path_hygiene.py) | 硬规则 7 机制性把关：入库文件零本机路径 |
| [_stub_mcp_server.py](../tests/_stub_mcp_server.py) | 测试用桩 stdio MCP server（不依赖 SDK、不做真实 I/O） |

**契约类用例的价值**：它们挡的都是「静默失效」（模式写错名、容器不可用却裸跑、preset 少一个文件就从选择器消失、审计配对错导致结论看起来可验），因此断言的是**机制与错误消息**，不是实现细节。

### 12.2 评测骨架（[examples/benchmark.py](../examples/benchmark.py)）

| 套件 | 内容 | 依赖 | 耗时量级 |
|---|---|---|---|
| `ctf` | 33 道离线 CTF 题（复用 `eval_ctf_solve.py` 的声明式题集） | 纯离线 | 秒级（CI 能力闸门） |
| `pentest` | 本地演示靶（`examples/target.py`）侦察并逐项断言预期发现 | 本机端口 | 秒级 |
| `lab` | 真实靶场基线（DVWA / Juice Shop / sw-secure-lab）被动侦察 | 靶场在跑 | 秒级 |
| `agent-lab` | agent 自主侦察真实靶场（真 LLM 决策） | LLM + 靶场 | 分钟级、有实际花费（`all` **不含**它） |
| `g07` | 07 靶场仿真（`warfare`） | `PENTEST_G07_ROOT` | 秒级 |
| `dsh-session` | 判定 DSH 宿主会话（读宿主桥证据链） | 离线 + spool | 秒级 |

- 结果模型：`CaseResult`（[L53](../examples/benchmark.py#L53)）+ `Scorecard`（[L53](../examples/benchmark.py#L53) 起），含通过率、平均步数、耗时、分类统计与序列化；`Scorecard.compare(baseline)` 逐例给出 `fixed` / `regressed`（**新增用例不计回归**）。
- `SUITES` 注册表（[L681](../examples/benchmark.py#L681)）与 `run(...)` 编排（[L698](../examples/benchmark.py#L698)）。
- 退出码：有失败用例即非零（[L827](../examples/benchmark.py#L827)）。
- 主要参数：`--suite / --driver / --out / --compare / --target / --port / --max-steps / --labs / --seed-skills / --reset-memory / --preset / --repeat`。

### 12.3 其它评测脚本

| 脚本 | 职责 | 依赖 |
|---|---|---|
| [eval_mode_switch.py](../examples/eval_mode_switch.py) | 阶段一验收演示：同一内核 + 同一目标，两种模式跑出不同判定（离线 mock，不发真实请求） | 离线 |
| [eval_ctf_solve.py](../examples/eval_ctf_solve.py) | 阶段二验收：CTF Crypto/Misc 端到端解题（**声明式题集**：加题只需在 `*_CASES` 表加一行） | 离线（`python_solve` 需沙箱档位） |
| [eval_evolution.py](../examples/eval_evolution.py) | 自我进化效果量化（有无技能对比，序列模拟） | 07 靶场 |
| [eval_evolution_llm.py](../examples/eval_evolution_llm.py) | 同上但用真实 LLM 决策（`--mock` 可打桩） | LLM + 07 靶场 |
| [eval_closed_loop.py](../examples/eval_closed_loop.py) | 四层策略叠加收益（基线 / Q 学习 / PPO） | 07 靶场（PPO 层需 torch） |
| [train_policy.py](../examples/train_policy.py) / [train_ppo.py](../examples/train_ppo.py) | RL / PPO 策略训练与对比 | 07 靶场（PPO 需 torch） |
| [target.py](../examples/target.py) | 授权本地演示靶（简易 HTTP 服务，三个端点） | 无 |
| [lab.py](../examples/lab.py) / [lab_agent.py](../examples/lab_agent.py) | 真实靶场被动侦察基线 / agent 自主侦察评测 | 靶场在跑（后者需 LLM） |
| [mcp_e2e_probe.py](../examples/mcp_e2e_probe.py) | MCP 联调探针（真实连接外部 MCP server 并列举工具） | 外部 MCP server |

---

## 13. 扩展指南

**新增一个工具**（不改内核代码）：

1. 若是外部 CLI：在 `penagent/external_tools.json`（或 `ctf_tools.json`）加一条，声明 `command / parameters / timeout / dangerous / positional / sandbox / network`，参数级 `flag` 可覆盖默认 `--key` 渲染。
2. 若是外部 MCP server 的工具：在 `penagent/mcp_servers.json` 声明 server（`transport / command|url / modes / tool_filter / tool_overrides / dangerous`），需 `--discover-mcp` 显式连接；大工具面的 server **必须**用 `tool_filter` 收窄。
3. 若是内核内置能力：在 `builtin_tools.py` 写函数并在 `register_builtins` 注册 `ToolSpec`（含 URL 边界与脱敏处理的务必复用既有原语）。
4. 最后：在目标模式的 `capability.allow` 里**写真实工具名**（或前缀通配），并跑 `tests/test_modes.py` 的真名核对用例。

**新增一个模式**：在 `modes/` 加 YAML（可 `inherits: base`），提供 `persona.system_prompt` 指向的提示词文件；`load_mode` 会做全字段校验。若要 Web/命令可选，文件名即 id（`base.yaml` 会被自动排除）。

**新增一个宿主/入口**：装配顺序固定为 `build_center(...)` → `mode` → `ModeProfile.filtered_registry` → 挂 `PolicyGate` → `PenAgent`。**不要把闸门写在调用方**——闸门挂在 `ToolRegistry` 上才对所有入口生效。

**沉淀技能**：任务跑完后 `python -m penagent reflect <mission_id>`（技能入库前必须通过证据引用校验）；需要内置经验时改 `skill_seeds.py` 的 `SEED_SKILLS` 并 `skills --seed --refresh`。

**改 DSH preset**：改 `_shared/agent.cordis.template.yml`（或 `_shared/*.mjs`），然后 `python tools/dsh_install.py` 同步 + 校验；**不要**把 preset 目录改成链接，也**不要**把裁决逻辑挪到 host 平面（作用域派发决定了收不到 preset 内的工具调用）。

---

## 14. 已知限制与文档索引

### 14.1 已知限制

- `budget.max_cost_usd` 为**预留字段**：OpenAI 兼容网关普遍不回传 token 用量，可靠计量前不做硬约束。
- `sandbox: docker` 需要可用的 Docker（或 WSL2 后端）；容器不可用时相关工具**被拒绝**（这是设计意图，不是缺陷）。无容器环境请按 `docs/沙箱降级评估.md` 显式改 `sandbox: local`。
- `rsactf_attack` 维持宿主直跑（离线数学攻击、无网络出口），人工把关由 `require_confirm` 档承担；结论登记在 `penagent/ctf_tools.json`，由契约用例锁定。
- radare2 MCP（`PENTEST_WSL_DISTRO` / `PENTEST_R2MCP_BIN`）暂未接线（上游 `r2mcp tools/list` 死锁）。
- DSH 侧 UI 点击级验收（R-33）受桌面浏览器传输限制，可用系统浏览器打开 token URL 绕过。
- DSH 升级后 preset 可能从选择器**静默消失**（基座引用的包被改名/移除）——先跑 `roster` 检查（见 `docs/DSH宿主接入指南.md`）。

### 14.2 文档索引

| 类别 | 文档 |
|---|---|
| 设计依据 | [渗透测试Agent调研报告-多模式切换.md](渗透测试Agent调研报告-多模式切换.md)（主报告：竞品/资产/路线/方案）、[个人渗透Agent产品设计.md](个人渗透Agent产品设计.md)（XPentest 设计基线）、[红队平台自建方案-SRC渗透流水线.md](红队平台自建方案-SRC渗透流水线.md)（"手脚与大脑分层"原则）、[开发提示词手册.md](开发提示词手册.md)、[XPentest内核README.md](XPentest内核README.md) |
| 阶段验收 | [阶段一验收报告.md](阶段一验收报告.md)、[端到端实战演练.md](端到端实战演练.md) |
| 宿主与界面 | [DSH宿主接入指南.md](DSH宿主接入指南.md)、[DSH主体化改造方案.md](DSH主体化改造方案.md)、[DSH主体化交付说明.md](DSH主体化交付说明.md)、[DSH插件化与内核旁路治理.md](DSH插件化与内核旁路治理.md)、[DSH高度融合与工具生态补强规划.md](DSH高度融合与工具生态补强规划.md) |
| 真机实测记录 | [DSH宿主实测记录.md](DSH宿主实测记录.md)、[Web真内核实测记录.md](Web真内核实测记录.md)、[RL链路实测记录.md](RL链路实测记录.md) |
| 度量与治理 | [评测骨架.md](评测骨架.md)、[能力加强路线.md](能力加强路线.md)、[修复待办清单.md](修复待办清单.md)、[沙箱降级评估.md](沙箱降级评估.md) |

---

## 附录 A：术语表

| 术语 | 含义 |
|---|---|
| ModeProfile | 模式档案：多模式切换的一等公民，加载即校验、运行期不可变 |
| capability | 模式对工具的 allow/deny/constraints 裁决 |
| permission 档位 | `ok`（放行）/ `ask`（待人工确认）/ `deny`（硬拒绝） |
| PolicyGate | 工具执行闸门：协议白名单 + 目标白名单 + 高危授权 |
| SandboxPolicy | 沙箱分档裁决：`none / local / docker`；容器不可用即拒绝 |
| Verifier | 成功判定器：`evidence_chain`（渗透）/ `flag_regex`（CTF） |
| 反幻觉 | 结论必须引用真实存在的证据 seq；编造引用直接判失败且不给重试 |
| memory_namespace | 记忆/技能库分区，模式间不互串 |
| fingerprint | 目标特征（自动推导或 LLM 提炼），用于技能匹配 |
| exposure | 技能的对抗暴露度（越低越隐蔽），`--stealth` 时优先注入 |
| ToolCenter | 统一工具注册中心：登记 → 发现 → 按模式构建注册表 |
| `mcp__proteus__*` | DSH 会话里内核 MCP server 暴露的工具命名 |
| SESSION_KEY | 会话状态隔离键：三个 preset 共用 `data/` 时按它分文件 |
| spool | 宿主桥落盘的原始事件文件（`data/dsh-events.jsonl`），由 `dsh-sync` 并入证据链 |