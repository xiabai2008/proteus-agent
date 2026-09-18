# Proteus · 千面 — 多模式渗透测试 Agent

> **一个内核，千种面孔。**
> Proteus（普罗透斯）：希腊神话中的海上老人，可随心变换任意形态——多模式切换的完美隐喻。
> 千面：一个内核，适配千种作战场景。

**仓库命名**：`proteus-agent`（GitHub `xiabai2008/proteus-agent`，命名空间已核验可用，2026-09-17）

---

## 一、项目定位

支持多模式切换的渗透测试 Agent：同一套内核，通过 ModeProfile（模式档案）在**常规渗透测试模式**、**CTF 比赛模式**等场景之间机制性切换——工具白名单、参数冻结、权限档位、预算策略、成功判定器全部随模式生效。

**主推架构（方案 C 为主线 + 方案 D 为宿主层）**：

```
宿主层（双入口，能力同一套）
  入口一 · 自有 CLI / Python SDK（独立运行，可进 CI）
  入口二 · DSH agent-preset 插件（白拿沙箱 / 审批 / Web UI）
        │
模式层 · ModeProfile（一等公民，本次新建的核心）
  persona / capability / permission / budget / scope / verifier / skills / sandbox
        │
内核层 · XPentest（Python 7210 行 · 64 测试，已有）
  ReAct 决策循环 · 证据链反幻觉 · 记忆与技能进化
        │
工具层 · MCP 统一注册（新增能力不改内核）
  RayScan · Chameleon · poxiao · ruoyi-scan · LogicHunt · 本地 70+ 二进制
        │
环境层 · 隔离与边界（模式可覆盖）
  Docker/WSL2 · 目标白名单硬校验 · 网络出口策略
```

**两条硬规则**：
1. 模式约束必须在**工具执行前**机制性生效（如 safe 模式下 `nuclei: null` 直接禁用），不能只写在提示词里靠模型自觉。
2. **可插拔 Verifier（成功判定器）是 CTF 与渗透模式的分水岭**：CTF 挂 `flag_regex`，渗透挂 `evidence_chain`。

---

## 二、为什么叫 Proteus · 千面

| 候选名 | 中文 | 结论 |
|---|---|---|
| **Proteus（选定）** | **千面** | 变形海神，随心换形；"千面"对齐既有命名风格（破晓/淬火/逻猎/星图/语巢），双关"多模式"与"红队伪装" |
| Janus | 双面/双阙 | 双面门神，贴合"双模式 + 双入口"，但暗示只有两种模式，格局小了 |
| Mirage | 蜃楼 | 红队幻象味浓，偏攻防对抗叙事，不强调模式机制 |
| Kaleido | 万华 | 一个筒千种图案，意象美但偏视觉，与渗透无强关联 |

避开"破晓"（已被 poxiao 与 dawnforge-pentest 同时占用，本就存在撞名）。

---

## 三、路线决策（2026-09-17 定稿）

| 路线 | 结论 | 一句话理由 |
|---|---|---|
| A 从零完全自研 | **排除** | XPentest 7210 行就是答案，成本已付过 |
| B 魔改 deepseek-harness 当内核 | **不作为主线** | TS/Cordis 与全 Python 资产的跨语言鸿沟；Windows 沙箱实际关闭；无取证反幻觉；上游是 RC 版会 breaking |
| **C 自有内核 + MCP 工具化 + 宿主双入口** | **主线** | 复用已有内核/工具/技能，边际成本最低；全栈自有代码叙事最强；不跟随上游 |
| D DSH 宿主插件化 | **C 的宿主层，并行推进** | agent-preset 挂载点干净，不改核心代码即可白拿沙箱/审批/Web UI/AgentTeams |

依据你自己定下的原则（《红队平台自建方案》）：**手脚不依赖大脑也能跑——dsh 挂了，CLI 照常能用。**

---

## 四、目录导航

```
proteus-agent/
├── README.md                                  本文件（项目主页）
├── docs/                                      现行文档（调研与设计基线）
│   ├── 渗透测试Agent调研报告-多模式切换.md       主报告：竞品/资产/路线/方案（2026-09-17）
│   ├── 渗透测试Agent调研报告-多模式切换.html     同内容浅色阅读版
│   ├── 个人渗透Agent产品设计.md                 XPentest 设计基线（LLM 决策第一原则/进化闭环）
│   └── 红队平台自建方案-SRC渗透流水线.md         "手脚与大脑分层"架构原则出处
├── archive/                                   2026-08 旧版调研（已被 09 版收敛取代）
│   ├── 网安agent渗透调研报告-团队版.md
│   ├── 网安agent渗透调研报告.md
│   ├── _research_t1_output.md
│   └── _research-pentest-agent.cjs
└── tools/
    └── md2html.py                             MD 转单文件 HTML（浅色主题），改文档后重新生成阅读版
```

**代码资产（保持原位，不搬迁——路径被 opencode.json 与 external_tools.json 引用，动了会断）**：

| 资产 | 位置 | 角色 |
|---|---|---|
| XPentest 内核 | `<WS>\网安项目开发规划\10-pentest-agent\` | 方案 C 的内核（`penagent/` 包） |
| DawnForge 技能库 + modes.yaml | `<WS>\dawnforge-pentest\`（部署副本 `<TOOLS_DIR>\`） | 方案 C 的技能层 + 模式雏形 |
| 工具军火库（约 70 个二进制） | `<TOOLS_DIR>\{bin,tools}` | 工具层，配置化注册 |
| deepseek-harness | `<WS>\deepseek-harness\` | 方案 D 宿主（只配不改） |
| RayScan / Chameleon（已 MCP 化） | `<WS>\RayScan\` / `Chameleon\` | 工具层首批接入 |

> 代码迁入本仓库的时机：等方案 C 阶段一动工（ModeProfile 落地）再把内核 fork 进来独立成仓；现在搬会断 `10-pentest-agent` 与工作区 git、opencode.json 的关联。

---

## 五、当前状态（2026-09-18）

三阶段已全部完成并通过真机验证：

| 阶段 | 状态 | 验证证据 |
|---|---|---|
| 一 · 模式抽象 | 完成 | ModeProfile + 可插拔 Verifier（evidence_chain / flag_regex）+ 记忆按模式分区；验收报告见 `docs/阶段一验收报告.md` |
| 二 · 能力补齐 | 完成 | MCP 统一注册中心 + CTF Crypto/Misc 工具链 + 沙箱分级（无容器时拒绝而非裸跑） |
| 三 · 宿主与界面 | 完成 | DSH agent-preset（24 工具挂载）+ Web 控制台三视图（真内核 / scripted 双驱动） |

**测试**：带 torch 204 passed；无 torch 165 passed + 3 skipped（RL 进化链路为可选依赖）。双解释器独立复跑核实。

**三链路真机实测**（记录见 docs/）：DSH 宿主（preset 发现 / stdio 拉起 / mcp-client 真实调用）· Web 真内核（LLM 决策 + SSE 步骤流 + 证据链 integrity）· RL 进化（步数 6.0→3.0，-50%；闭环评测 Q 层 -39% / PPO 层 -42%）。

**安全姿态**：PolicyGate 由 ToolRegistry 持有，目标白名单 + 高危授权在 ReAct / MCP / Web 全入口机制性生效；MCP 失败语义修正（isError）；ctf-* 模式的脚本执行强制沙箱档位，无容器环境拒绝而非裸跑。

**下一步**：端到端实战演练（CTF 三题 + 授权靶场渗透流程）· RayScan / Chameleon MCP 联调 · 竞赛 / 毕设叙事材料。

---

> **安全声明**：仅用于授权范围内的受控安全实验（自有靶机 / CTF 靶场 / 隔离容器）。目标白名单硬校验 + 高危操作审批 + 全动作证据链留痕是不可妥协的前提。严禁在未授权系统上运行。
