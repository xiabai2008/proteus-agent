# Proteus · 千面 — Agent 开发上下文（AGENTS.md）

> 本文件是所有 AI 编码会话的唯一事实来源。开工前必读；与你的理解冲突时，以本文件为准。
> 项目主页见 `README.md`，完整调研依据见 `docs/渗透测试Agent调研报告-多模式切换.md`。

## 1. 你在开发什么

多模式渗透测试 Agent：同一套 Python 内核，通过 **ModeProfile（模式档案）** 在「常规渗透测试模式」「CTF 比赛模式」等场景间**机制性**切换。当前执行**方案 C（主线）+ 方案 D（宿主层）**：

- 内核 = XPentest（已存在，fork 进本仓库），ReAct 循环 + 证据链反幻觉 + 记忆与技能进化
- 工具层 = MCP 统一注册（RayScan / Chameleon 已有 MCP Server；poxiao / ruoyi-scan / LogicHunt / 本地二进制待接）
- 宿主层 = 双入口：自有 CLI/SDK（必须可独立运行）+ deepseek-harness agent-preset（可选）

## 2. 不可违反的硬规则（每次改动前自查）

1. **模式约束必须在工具执行前机制性生效**（禁用即拒绝执行），禁止只写在 system prompt 里靠模型自觉。
2. **不得削弱证据链反幻觉语义**（`evidence.py` 的链式哈希与 `valid_refs` 引用校验是底线；结论引用不存在的证据必须判失败）。
3. **目标白名单硬校验不可绕过**：任何模式下，越界目标一律拒绝；高危工具必须过 permission 档位（ask / auto / deny）。
4. **内核不得依赖任何宿主**：不 import DSH / Claude Code 专属能力；宿主只通过 MCP 或子进程调用内核。
5. **不引入重型新依赖**：先看 `requirements.txt`；能用 stdlib / dataclass 就不引 Pydantic / LangChain（确需引入先在回复中说明理由）。
6. **每次任务收尾必须**：全量 `pytest` 绿 + 一次 git commit（新功能与测试同一提交）。
7. **路径红线**：不移动 `<WS>` 下其他项目（poxiao / RayScan / deepseek-harness 等）；配置里的路径一律写 `${VAR}` 占位符，**禁止把本机绝对路径写进任何入库文件**。
8. **合法授权前提**：默认目标白名单仅 127.0.0.1/localhost；`.env` 含密钥，不入库（用 `.env.example`）。

## 2.1 环境变量约定（可移植性）

本机真实路径只存在于不入库的 `.env`，由 `penagent/envcfg.py` 统一装载与展开：

| 变量 | 含义 | 消费方 |
|---|---|---|
| `PENTEST_WS` | 工作区根（poxiao / RayScan / 本仓库等所在目录） | external_tools.json / mcp_servers.json / adapters / DSH preset |
| `PENTEST_TOOLS` | 本地工具库根（httpx/nuclei 等 ~70 个二进制） | external_tools.json |
| `PENTEST_PY312` | Python 3.12 解释器路径 | DSH preset（容器外 CLI） |
| `PENTEST_G07_ROOT` | 07 靶场（warfare 包）根 | conftest.py / 评测脚本 |
| `PENTEST_DOCKER_IMAGE` | 沙箱容器镜像（缺省 python:3.12-slim） | penagent/sandbox.py |

规则：配置 JSON 与入库文件写 `${VAR}`；`envcfg.expand_deep()` 在装载时展开，未设置的变量保持原样（运行时存在性校验会给出"未注册/不可用"，不崩溃）。新增路径类配置一律走这个机制，禁止回退到硬编码。

## 3. 关键事实

- 语言/运行时：Python 3.12（现有 pyc 为 cpython-312）；Windows + bash；测试框架 pytest。
- 内核来源：`<WS>\网安项目开发规划\10-pentest-agent`（fork 时只拷 `penagent/`、`tests/`（排除 `_tmp*`、`__pycache__`）、`pytest.ini`、`requirements.txt`；`.env` 不拷，另建 `.env.example`）。
- 内核现有模块：`agent.py`（ReAct 循环 + Policy 护栏）、`evidence.py`、`memory.py`（missions/skills）、`reflect.py`、`tools.py` + `external_tools.json`、`llm.py`、`mcp.py`（10 工具）、`gaps.py`、`ppo.py`/`rl.py`、`adapters/`。
- 已知重构点：`agent.py` 的 `Policy.authorize` 是硬编码布尔值、`SYSTEM_PROMPT` 是模块级常量——这两处是模式化的改造入口。
- 模式雏形参考：`<WS>\dawnforge-pentest\config\modes.yaml`（tool_constraints 机制性禁用的做法直接借鉴）。
- CTF 现状：`dawnforge-pentest/skills/pentest_skills/ctf-*` 只有 SKILL.md 文档，无实现；本地已有 rsactftool / jadx / x64dbg 等二进制（`<TOOLS_DIR>\bin`）。
- RL 进化链路（`ppo.py` / `rl.py` + `examples/eval_evolution.py`、`eval_closed_loop.py`）：**已验证**（2026-09-18，命令与原始输出见 `docs/RL链路实测记录.md`）。
  环境：pytest 解释器 `<PY312>\python.exe` 上装的是 `torch 2.8.0+cpu`；torch 保持**可选依赖**定位不变（硬规则 5，不进 `requirements.txt` 安装列表），屏蔽 torch 时 165 passed / 3 skipped，就位后 173 passed / 0 skipped。
  数据：`eval_evolution.py` 决策步数 6.0 → 3.0（下降 50%，与内核 README 声称一致）；`eval_closed_loop.py` 四层叠加为基线 4.28 → Q 学习 2.60（-39%）→ PPO 2.50（-42%），三次重跑逐位一致。
- 外部依赖 **07 靶场**：两个评测脚本需要 `warfare` 仿真包，位于 `<WS>\网安项目开发规划\07-agent-war-range`（注意**不在** `<WS>\07-agent-war-range`）。`conftest.py` 按 `PENTEST_G07_ROOT` → 相邻布局 → 本机绝对路径的顺序解析并注入 `PYTHONPATH`（供测试用 subprocess 拉起的评测脚本继承）；直接跑脚本时须自行设 `PYTHONPATH`，否则报 `ModuleNotFoundError: No module named 'warfare'`。

## 4. ModeProfile 规范（阶段一的核心交付）

模式文件放 `modes/` 目录，YAML 格式，支持 `inherits` 单继承；加载时合并校验，运行期不可变。

字段与语义：

| 字段 | 语义 | 生效点 |
|---|---|---|
| persona.system_prompt | 模式提示词模板 | 组装 system prompt |
| capability.allow / deny / constraints | 工具白名单 / 黑名单 / 参数冻结追加 | **工具执行前裁决** |
| permission.default / auto_approve / require_confirm / hard_deny | ok / ask / deny 档位 | 工具执行前裁决 |
| budget.max_steps / max_minutes / max_cost_usd / model_tier | 步数 / 时长 / 成本上限，超限换策略而非硬退出 | 主循环计数 |
| scope.target_allowlist / network_egress | 目标范围 / 出网开关 | Policy 校验 |
| verifier.type / pattern / auto_retry | 成功判定器：`evidence_chain`（渗透）或 `flag_regex`（CTF） | 任务收口 |
| skills | 本模式技能包 | 技能检索过滤 |
| memory_namespace | 记忆/技能库分区（模式间不互串） | Memory 读写 |
| sandbox | 隔离级别声明 | 阶段二实装，先落字段 |

两个基准模式（照此落盘）：

```yaml
# modes/pentest-standard.yaml
id: pentest-standard
label: 常规渗透测试模式
inherits: base
persona: {system_prompt: prompts/pentest.md, output_format: markdown_report}
capability:
  allow: ["*"]
  deny: ["msf_exploit", "webshell_write"]
  constraints: {nuclei: "-severity low,medium,high -c 25", sqlmap: "--batch --level 3 --risk 1", fscan: "-nobrute"}
permission:
  default: ask
  auto_approve: ["httpx", "subfinder", "dnsx"]
  require_confirm: ["sqlmap", "ffuf", "hydra"]
  hard_deny: ["mimikatz", "ransomware_sim"]
budget: {max_steps: 40, max_minutes: 180, max_cost_usd: 5.0, model_tier: {recon: cheap, reason: strong}}
scope: {target_allowlist: required, network_egress: false}
verifier: {type: evidence_chain, require_poc: true}
skills: [web-recon, sqli, ssrf, report-gen]
memory_namespace: pentest-standard
sandbox: docker
```

```yaml
# modes/ctf-web.yaml
id: ctf-web
label: CTF Web 模式
inherits: base
persona: {system_prompt: prompts/ctf.md, output_format: raw_flag}
capability:
  allow: [http_test, browser_auto, script_run, file_read, crypto_tools]
  deny: [nuclei, fscan, sqlmap]
budget: {max_steps: 60, max_minutes: 20, max_cost_usd: 1.0}
scope: {network_egress: true}
verifier: {type: flag_regex, pattern: '(?i)(flag|ctf)\{[^}]+\}', auto_retry: 3}
skills: [ctf-web]
memory_namespace: ctf-web
sandbox: docker
```

## 5. 阶段计划与验收标准

| 阶段 | 内容 | 验收标准（可自检） |
|---|---|---|
| 一 · 模式抽象 | fork 内核 → ModeProfile 模型与加载器 → Policy 模式驱动化 → 双 Verifier → memory 按模式分区 | 同一内核同一目标两种模式输出不同判定；被模式禁用的工具发起调用被机制性拒绝；全量 pytest 绿 |
| 二 · 能力补齐 | MCP 注册中心统一接入 + CTF Crypto/Misc 工具 + 沙箱实装 | 新增工具不改内核代码；CTF 模式自动解出至少 3 道 Crypto/Misc 题 |
| 三 · 宿主与界面 | DSH agent-preset 插件 + Web 控制台 + 多 agent 并行 | DSH 界面可选模式/下任务/看证据链 |

## 6. 工作约定

- 接到任务先说 3 句以内的实现方案（改哪些文件、新增哪些），确认后动手；小改动可直接动手。
- 实现 → 补测试（新逻辑必须有对应用例）→ 全量 pytest → commit，一次完成，不拆散。
- commit message 用中文一行式：`阶段一: Policy 升级为模式驱动裁决`。
- 报错时贴完整 traceback 给你；你先定位根因再改，不做绕过式修补。
- 文档与注释用简体中文；代码、标识符、YAML 键用英文；不使用 emoji。
