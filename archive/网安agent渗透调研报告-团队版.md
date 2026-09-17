# AI 网安 Agent 渗透测试现状调研报告

> **调研任务**：t3 汇总撰写对比报告与落地建议（analyst 执笔）
> **上游原料**：`t1_academic_opensource_frameworks.md`（学术与开源，researcher-1）、`t2_commercial_toolchain.md`（商业与工具链，researcher-2）
> **数据时点**：2025–2026（含 arXiv/GitHub 一手抓取）
> **适用范围**：AI 驱动的网络安全 Agent 渗透测试（agentic penetration testing）现状、能力边界与落地建议，供红队 / 蓝队 / 个人研究者参考。
>
> ⚠️ **安全声明**：本报告涉及的技术全部基于文献、厂商公开资料与受控靶场评测，**仅用于授权范围内的受控安全实验**，严禁在未授权真实系统上运行。

---

## 一、现状总览：学术/开源 vs 商业/工具链

AI 网安 Agent 渗透测试在 **2025–2026 年进入快速爆发期**，但"学术/开源"与"商业/工具链"两条线呈现截然不同的成熟度与发展节奏。

### 1.1 学术与开源线：研究活跃、全自动仍不可靠

- **演进主线清晰**：从早期 **PentestGPT（2308.06782，解决 LLM 长上下文丢失）→ PentestAgent（RAG+多智能体）→ 显式规划/难度感知/防守对抗**（CHECKMATE/PEP、ZERO-APT、Excalibur、xOffense、Red-MIRROR）。研究方向从"能不能自动打"转向"如何稳定地自动打（规划/状态管理/难度评估）"。
- **"端到端全自动"仍是硬伤**：**AutoPenBench 测出全自动 agent 端到端成功率仅 21%**（简单任务 27%，真实世界仅 1 个）；**PentestEval 端到端仅 31%，自治 agent 几乎全部失败**。当前可靠形态是**人机协同（半自动）**——AutoPenBench 显示辅助式可达 **64%**。
- **开源生态成熟度分层明显**：PentestGPT 社区最大（约 14.8k star），其余多为研究原型或实验台。真正可复用的"实验基础设施"（如 Cochise 的 630 行 Planner-Executor 参考实现 + GOAD 日志语料）正在涌现，但普遍**面向 CTF/靶场，真实网络渗透覆盖有限**。
- **基准评测百花齐放但口径不一**：CVE-Bench（真实 Web CVE 利用）、AutoPenBench（33 任务分层）、PentestEval（6 阶段 346 任务）、CyberSecEval、HackSynth CTF 集、ZERO-APT（对抗防守）等，各自标准不同，**直接横向对比需谨慎**。

### 1.2 商业与工具链线：落地快速、但宣传与真相有落差

- **国际**：以 **XBOW**（2025 独角兽、HackerOne 登顶 #1，主打"零误报"）为代表的全自主渗透；**Pentera / Horizon3 NodeZero / SafeBreach / AttackIQ** 为代表的"验证型 AEV"（验证防护是否真能拦截）；**Anthropic Mythos / Project Glasswing** 的"最强模型厂商亲自下场"；**Cobalt / Terra / BreachLock** 的"human-led, AI-powered / 人机结合（HITL）"；以及 **Aikido / RunSybil / Strix** 等 dev-first 或开源动态审计。
- **国内**：面向政企/护网/攻防演练密集发布——**绿盟 AI-PTS（8.8 万漏洞知识图谱+8600 POC）、奇安信 AI加特林、360 破阵子、安恒恒脑、长亭 AI 自主渗透智能体、墨云 VackBot、悬镜灵脉、斗象蛙池、阿里云 Agentic BAS**。2026-07 出现"AI 渗透测试等 AI 安全产品密集发布"行情。
- **工具链 MCP/API 化成为统一趋势**：安全工具正快速封装成 **MCP（Model Context Protocol）server** 供 LLM agent 调用——**Metasploit 官方正合入 MCP 支持（PR #21315）**、ZAP 官方 MCP server、BloodHound 官方 MCP（攻击路径查询）、**Horizon3 NodeZero 官方 MCP**、Nuclei 官方 AI 扩展，社区还有 security-mcp-suite、hexstrike-ai、Kali MCP server 等组合型。**MCP 已成 LLM Agent 调用渗透工具的标准接口**。

### 1.3 一句话总览

> **学术/开源**提供**可审计、可复现的"能力地基"与评测基准**，但全自动不可靠、需人机协同；**商业/工具链**提供**工程化落地、可交付的产品形态与统一接口（MCP）**，但多黑盒、技术披露有限、存在宣传水分。二者互补，但**共同能力天花板=端到端全自动可靠性**，尚无人完全突破。

---

## 二、能力矩阵对比表

> 说明：为便于横向对比，下表把"学术/开源框架"与"商业/工具链"合并到一张能力矩阵，按"自主程度 / 验证程度 / 适用者"归纳。星级为用户侧相对评估（并非厂商口径），仅供参考。

### 2.1 代表性方案能力矩阵

| 方案 | 类别 | 形态 | 自主度 | 验证/误报水平 | 目标场景 | 面向人群 | 关键证据/局限 |
|---|---|---|---|---|---|---|---|
| **PentestGPT** | 学术/开源 | 开源工具 | 60%（半自动） | 中（依赖基座模型） | Web/CTF | 个人研究者 | 最成熟开源框架，1.4万 star；端到端全自动弱 |
| **PentestAgent** | 学术/开源 | 论文/框架 | 60% | 中 | 情报/漏洞/利用三阶段 | 研究者 | RAG+多智能体，评测受基准影响 |
| **AutoAttacker** | 学术/开源 | 论文/系统 | 中 | 中 | Pre-breach→后利用 | 研究者 | 攻击库覆盖有限，仓库未维护 |
| **HackSynth** | 学术/开源 | 开源框架 | 70% | 中 | CTF（PicoCTF+OverTheWire） | 研究者/学习者 | Planner+Summarizer，GPT-4o 最佳，AGPL |
| **Cochise** | 学术/开源 | 开源实验台 | 参考实现 | 实验级 | 内网（SSH/GOAD） | 研究者 | 630 行 Python，Planner-Executor，非 SOTA 但可复现 |
| **xOffense** | 学术/开源 | 论文/框架 | 80% | 中 | AutoPenBench 等多任务 | 研究者 | 领域微调 Qwen3-32B+多智能体，子任务完成率 79.17% |
| **Excalibur** | 学术/开源 | 论文 | 高（需前沿模型） | 高 | CTF/GOAD | 研究者 | 难度感知规划，Type A/B 失败分类，CTF 91%、GOAD 4/5 主机 |
| **Red-MIRROR** | 学术/开源 | 论文/框架 | 高 | 高 | 复杂 Web 利用 | 研究者 | RAG+共享记忆+双相反思，XBOW 基准 86% SR |
| **APT-Agent** | 学术/开源 | 论文/框架 | 高 | 中 | Metasploitable2 | 研究者 | 混合纠错+命令记忆，Metasploitable2 端到端 84.29% |
| **ZERO-APT** | 学术/开源 | 论文/框架 | 高 | 中 | Windows AD 后利用 | 研究者/蓝队 | 攻防判三方、可审计 CTI 报告 |
| **CVE-Bench**（基准） | 学术 | 基准/数据集 | — | 高 | 真实 Web CVE 利用 | 评估者 | 评测真实漏洞利用能力的标准之一 |
| **AutoPenBench**（基准） | 学术 | 基准 | — | 高 | 33 任务分层 | 评估者 | 全自动 21% / 辅助 64% 的关键基准 |
| **PentestEval**（基准） | 学术 | 基准 | — | 高 | 6 阶段 346 任务 | 评估者 | 端到端 31%，自治 agent 几乎全败 |
| **XBOW** | 商业 | SaaS 按次 | 高（全自主） | 厂商称"零误报"、第三方需复核 | 持续渗透/红队 | 中大型企业 | HackerOne #1、$4k/次；黑盒难独立验证 |
| **Pentera** | 商业 | 混合部署 | 中高 | 验证型（验证防护拦截） | AEV/合规 | 中大型企业 | ARR $1 亿，1200+ 客户，AEV 品类开创者 |
| **Horizon3 NodeZero** | 商业 | 自托管 runner+云 | 高 | 高（生产零影响） | RBVM/攻击路径 | 中大型企业 | 官方 MCP，扫描噪音→已验证修复项 |
| **Anthropic Mythos** | 商业 | 模型厂商产品 | 高 | 依托最强模型 | Agentic Security | 前沿/关键设施 | Project Glasswing 覆盖 150+ 关键基础设施 |
| **Cobalt / Terra / BreachLock** | 商业 | PTaaS/HITL | 中（人工+AI） | 高（人在回路） | 合规/持续渗透 | 中大型企业 | "human-led, AI-powered" 最易过审 |
| **Aikido / RunSybil** | 商业 | SaaS dev-first | 中高 | 中 | Web 应用/开发者 | 开发者/SaaS | 开发工作流集成，可复现 PoC |
| **Strix** | 商业/开源 | 开源+托管 | 中 | 高（动态+真实 PoC） | Web/API 代码审计 | 研究/自建 | 34k star，可自审计 |
| **国内政企平台**（绿盟/奇安信/360/安恒/长亭/墨云/悬镜/斗象） | 商业 | 平台/项目 | 中高 | 厂商口径不一 | 攻防演练/护网/等保 | 政企 | 8.8 万知识图谱+8600 POC 等储备；自信度需实测复核 |
| **阿里云 Agentic BAS** | 商业 | 云原生 | 中高 | 中 | 云上资产评估 | 云用户 | 通义千问多 Agent，云原生联动 |
| **开源工具链 + MCP**（Nuclei/Metasploit/ZAP/BloodHound/Interactsh/hexstrike-ai） | 开源工具链 | 工具+MCP | 60-80% | 中高 | 自建 agent 实验 | 研究者/红蓝队 | MCP 标准接口，DSH 落地自建首选 |

### 2.2 关键对比维度小结

| 维度 | 学术/开源 | 商业/工具链 |
|---|---|---|
| 可审计性 | ✅ 代码/论文完全开放 | ❌ 多黑盒、技术披露有限 |
| 端到端可靠性 | ⚠️ 全自动 21–31%，半自动 64% | ⚠️ 宣称高，但第三方质疑"炒作多于深度" |
| 工程化/交付 | ❌ 需自搭 | ✅ 成熟的产品形态与接口（MCP） |
| 基准支撑 | ✅ 有标准评测（CVE-Bench 等） | ❌ 极少公开可复现评测 |
| 成本 | 低（算力+token） | 高（按次 $4k/按资产年费/项目制） |
| 合规/法律 | 需自行确保授权 | 厂商提供合规框架（SOC2/等保） |

---

## 三、能力边界与风险

### 3.1 硬性能力边界（跨论文一致结论）

1. **"端到端全自动"远未成熟**
   - **AutoPenBench**：全自动端到端 **21%**（真实世界仅 1 个任务成功）；**辅助式（半自动）64%**。
   - **PentestEval**：端到端 **31%**，"自治 agent 几乎全部失败"。
   - **结论**：当前可靠形态是**人机协同**，不是全自主。

2. **失败模式分两类（Excalibur 2602.17622 归纳）**
   - **Type A**：能力空白（缺工具、提示词不当）→ 可工程快速修复。
   - **Type B**：规划/状态管理缺陷 → 根因是"缺乏任务难度实时评估"，导致时间花在低价值分支、**上下文过早耗尽**；**该类对底层 LLM 几乎不变**（单靠模型缩放无法根治）。

3. **侦察（recon）是主要瓶颈，而非利用**
   - 分离式评测（2606.25332）显示：**给定准确漏洞上下文时 agent 功能成功率可达 90%**，但**自主侦察阶段目标漏洞召回率仅约 50%**（主要原因：telemetry/信息摘取解析失败）。
   - 综述（2512.12326）也指出 AI 渗透 77% 集中在 RL、覆盖发现/利用阶段，**侦察与后利用薄弱**。

4. **长程规划与复杂推理不稳定**（CHECKMATE 综述结论）；**幻觉命令普遍**（APT-Agent 引入纠错模块直接用幻觉命令恢复方案，反证其普遍性）。

5. **评测结果依赖基座模型**：Claude Code/Sonnet 4.5、GPT-4o 在端到端演示当前最强，**远超前早期 PentestGPT 系**；开源/中规模模型（Qwen3-32B-ft）差距明显，但通过**领域微调+多智能体**可缩小（xOffense、Excalibur）。

### 3.2 风险清单

| 风险类别 | 具体表现 | 缓解建议 |
|---|---|---|
| **误报/虚报（误报）** | 商业"零误报"是宣传话术；AI pentesting "cried wolf" 后人工复查成本反升 | 用 CVE-Bench/AutoPenBench 做对照基线；坚持"可复现 PoC"验证；人机复核 |
| **越权/副作用（越权）** | Agent 未按受控路径执行、产生破坏性副作用；双刃剑（dual-use）风险（2507.00829） | 严格限定在隔离容器/靶机；NodeZero"生产零影响"思路；权限与范围硬约束 |
| **法律边界** | 未授权测试违法；责任归属模糊；自动化扩大攻击面（MCP tool poisoning 可把 agent 变内鬼） | 授权前提明确；仅在受控靶场/自己系统实验；记录可审计轨迹 |

---

## 四、选型建议

### 4.1 红队（追求真实攻击路径与自动化）

- **首选商业**：**XBOW**（全自主持续渗透+报告）或 **Horizon3 NodeZero**（攻击路径+RBVM+MCP 对接，生产零影响），搭配 **Pentera** 做防护有效性验证。
- **人机结合为本**：采用 **Cobalt / Terra / BreachLock** 的 HITL 模式——Agent 干活、人在回路复核，最易过审且副作用可控。
- **开源增强**：用 **Metasploit MCP / BloodHound MCP / Nuclei-ai** 构建自研 agent 增强既有红队流程。
- **注意**：全自主产品需 PoC 实测验证"零误报"等宣称，警惕黑盒不可审计。

### 4.2 蓝队（验证防护、漏洞管理闭环）

- **首选 AEV/BAS 验证型**：**Pentera、SafeBreach、AttackIQ** ——重点在**验证 EDR/防火墙/身份防护是否真能拦截**，而非单纯找洞。
- **攻击路径 + 修复闭环**：**Horizon3 NodeZero + MCP → RBVM**，把"扫描噪音"变成"已验证修复项"。
- **开源蓝队基线**：ZAP MCP + Interactsh（OOB 盲打确认）用于 Web 漏洞验证。

### 4.3 个人研究者 / 学习者（成本敏感、重可审计）

- **首选开源组合**：**PentestGPT**（起步低、社区大）+ **CVE-Bench / AutoPenBench**（标准评测）+ **HackSynth / Cochise**（轻量实验底座、日志可回放）。
- **优先选新架构**：带**外部规划/难度感知**的（CHECKMATE/PEP、Excalibur 思路），规避 **Type B 失败**。
- **个人零预算购买陷阱**：避免直接付费用"黑盒"商业产品买期待；先用开源做基线，再判断是否值得采购。

---

## 五、本机 DSH（DeepSeek Harness）环境落地建议

### 5.1 目标
在**本机受控靶场内**，组合开源工具 + agent 框架做**可复现、可审计**的受控渗透实验，验证 agent 能力并积累技能。**禁止在真实/未授权系统运行。**

### 5.2 推荐技术组合（自底向上）

```
┌─────────────────────────────────────────────────────┐
│ 应用/评测层（选一）                                    │
│  CVE-Bench（真实 Web CVE） / AutoPenBench（33任务分层） │
│  HackSynth CTF 集 / GOAD（AD 内网，配 Cochise 日志）   │
└──────────────────────┬──────────────────────────────┘
  标准评估（端到端 + 阶段成功率，双指标）
┌──────────────────────▼──────────────────────────────┐
│ Agent 框架层                                         │
│  PentestGPT（全链路 / 半自动主导）                     │
│  Cochise（Planner-Executor 轻量底座 + 日志回放）      │
│  HackSynth（Planner+Summarizer）                     │
└──────────────────────┬──────────────────────────────┘
  规划增强（选装）：外部规划 / 难度感知 / RAG 知识库
┌──────────────────────▼──────────────────────────────┐
│ 工具接口层（MCP/API 化标准接口）                      │
│  Nuclei-ai / ZAP MCP / Metasploit MCP / BloodHound   │
│  MCP / Interactsh（OOB 盲打确认）                    │
└──────────────────────┬──────────────────────────────┘
  模型底座：DSH 内可用的强推理模型（优先前沿模型，
  开源/中规模需领域微调+多智能体弥补差距）
┌──────────────────────▼──────────────────────────────┐
│ 隔离环境层                                            │
│  本地 Docker 容器 / VM，网络隔离，禁用外连真实目标     │
└─────────────────────────────────────────────────────┘
```

### 5.3 落地步骤建议

1. **搭隔离靶场**：本地 Docker Compose 一键起 CVE-Bench / AutoPenBench 或 HackSynth CTF 靶机；内网实验用 GOAD 配 Cochise 日志。**网络出站限制**，防止逃逸到真实目标。
2. **选底座 + 跑通基线**：先跑 Cochise/HackSynth 的 planner-executor，跑能复现 AutoPenBench 的 21%（全自动）/64%（辅助）基线，建立"我机器能跑多少"的对照。
3. **接入 MCP 工具链**：配置 ZAP MCP、Nuclei、Interactsh、Metasploit MCP 做工具编排；用 Interactsh 解决"agent 无法确认盲打漏洞"痛点。
4. **评测双指标**：**同时记录"端到端成功率"与"阶段成功率"**——否则会被利用阶段的高分误导（利用可到 90%，但侦察召回仅约 50%）。
5. **加入规划增强**：引入外部规划/难度感知（CHECKMATE/PEP、Excalibur 思路）规避 Type B；必要时用 RAG 知识库补足侦察能力。
6. **记录与审计**：复用 Cochise 的 replay/analyze 工具记录动作轨迹，保留可审计日志（对齐合规要求）。
7. **严守边界**：全部限定在靶机/隔离容器，严禁真实系统；对齐 OpenAI/Meta 安全实践。

### 5.4 落地中需警惕的坑

- **模型底座决定上限**：先用 DSH 内最强可用推理模型跑通，再评估是否值得上领域微调+多智能体。
- **成本 vs 收益**：agentic pentesting 隐藏成本（token、算力、人力复核、授权/合规）易被低估——本机实验建议设 token 预算与超时。
- **"零误报"不可信**：本机实验也要保留人工复核环节，勿盲信自动报告。

---

## 六、结论

1. **AI 网安 Agent 渗透测试处于"能力跃升前夜"**：学术提供可复现地基与评测，商业提供工程化交付与统一接口（MCP），但**端到端全自动可靠性仍是共同天花板**（全自动 21–31%，半自动 64%）。
2. **人机协同是当前最佳实践、也是商业主流叙事**（XBOW/Terra HITL、Cobalt "human-led, AI-powered"）；"全自主、零误报"应视为宣传话术而非成熟事实。
3. **能力边界明确**：利用强、侦察弱；Type B 规划/状态管理缺陷单靠模型缩放无法根治；幻觉命令、上下文耗尽、工具调用不可靠是主要失败模式。
4. **落地路径清晰**：个人/研究者用 **PentestGPT+CVE-Bench/AutoPenBench+Cochise/HackSynth** 在受控靶场起步，优先带外部规划/难度感知的新架构；企业红蓝队按 XBOW/Pentera/NodeZero/Terra/Cobalt 场景选型，并把**授权界限与人工复核**作为不可妥协的前提。

> 关键来源：t1（AutoPenBench: arxiv 2410.03225；PentestEval: arxiv 2512.14233；Excalibur: arxiv 2602.17622；CVE-Bench: arxiv 2503.17332 / github uiuc-kang-lab/cve-bench；PentestGPT: arxiv 2308.06782 / github GreyDGL/PentestGPT；CHECKMATE: arxiv 2512.11143；Cochise: arxiv 2605.11671）、t2（XBOW: xbow.com；Pentera: pentera.io；NodeZero: docs.horizon3.ai；Metasploit MCP: PR #21315；BloodHound MCP: specterops.io；ZAP MCP: zaproxy.org；国内厂商官方页）。个别国内产品细节以厂商官网为准。
