# 调研报告：学术与开源渗透测试 Agent 框架现状（task t1, researcher-1）

> 数据来源：arXiv API（export.arxiv.org）与 GitHub API（api.github.com）直接抓取（2026-08 时间戳），均为一手摘要/仓库元数据。web_search 因 provider 余额问题不可用，改用直连抓取。

---

## 一、核心结论（速览）

1. **学术研究已形成"单智能体 → 多智能体协作 → 外部规划增强"的演进主线**：早期 PentestGPT（2308.06782）解决 LLM 长上下文丢失问题；PentestAgent 引入 RAG+多智能体；2025-2026 年大量工作（CHECKMATE、ZERO-APT、Excalibur、xOffense、Red-MIRROR）转向显式规划机制、难度感知、防守对抗等。
2. **"端到端全自动"仍不可靠**：AutoPenBench 测出全自动 agent 端到端成功率仅 21%；PentestEval 端到端成功率仅 31%，"自治 agent 几乎全部失败"。当前可靠形态仍是**人机协同（半自动）**，辅助式可达 64%。
3. **基准评测在快速填补空白但口径不一**：CVE-Bench（真实 Web 漏洞利用）、AutoPenBench（33 任务分层）、AI-Pentest-Benchmark、CyberSecEval（Meta，侧重编码安全与风险/能力）、CTFusion / HackSynth 的 PicoCTF+OverTheWire、ZERO-APT（对抗型防守），彼此标准不统一。
4. **能力边界清晰**：枚举/利用强，侦察（recon）/信息解析弱（"reconnaissance recall 约 50%"）；幻觉命令、长程规划不稳定、上下文耗尽、工具调用不可靠是主要失败模式（CHECKMATE、Excalibur、2506.25332 均指出）。
5. **闭源前沿模型领先**：多篇独立评测一致认为 Claude Code / Claude Sonnet 4.5 与 GPT-4o 在端到端渗透演示中当前最强，远超 PentestGPT 等早期系统。

---

## 二、代表性学术项目 / 论文清单

| 项目/论文 | 类型 | 能力要点 | 局限 | 来源链接 |
|---|---|---|---|---|
| **PentestGPT** (GreyDGL) | 开源工具 / 论文 | 三模块（推理/生成/解析）自交互解决上下文丢失；相对 GPT-3.5 任务完成度提升 228.6%；Web 场景；GitHub 超 1.4 万 star，社区活跃 | 端到端全自动不足；依赖强推理模型；后经"Towards Automated Pentesting"评测证明 GPT-4o/LLaMA3.1-405B 亦难全自动完成 | https://arxiv.org/abs/2308.06782 · https://github.com/GreyDGL/PentestGPT |
| **PentestAgent** (nbshenxm/Shen et al.) | 论文 / 开源框架 | RAG 增强渗透知识 + 多智能体协作；覆盖情报收集、漏洞分析、利用三阶段；AsiaCCS 2025 | 需 RAG 知识库与多智能体编排；评测受基准选择影响 | https://arxiv.org/abs/2411.05185 · https://github.com/nbshenxm/pentest-agent |
| **AutoAttacker** (UCI DAN Lab, Fang 等) | 论文 / 系统 | LLM 引导的自动网络攻击执行：Plan-Generate-Execute 循环 + 攻击库枚举，推进 pre-breach→主/后利用全流程自动化 | 攻击库覆盖有限；对未知攻击形式泛化弱；仓库未维护 | https://arxiv.org/abs/2403.01038 |
| **HackSynth** (aielte-research) | 开源框架 / 论文 | Planner（计划）+Summarizer（反馈聚合）双模块迭代生成命令；自建 PicoCTF+OverTheWire 约 200 道 CTF 基准；GPT-4o 表现最佳 | 面向 CTF，真实网络/内网渗透场景有限；结果受采样参数影响；AGPL-3.0 | https://arxiv.org/abs/2412.01778 · https://github.com/aielte-research/HackSynth |
| **VMS (Vulnerability Mitigation System)** | 论文 / 系统 | 类似 HackSynth 的 Planner+Summarizer 架构，容器化安全环境限制危害 | 与 HackSynth 高度同源；CTF 导向，真实场景证据弱 | https://arxiv.org/abs/2507.21113 |
| **AutoPenBench** (Gioacchini et al.) | 基准 | 33 个易受攻击系统任务、分层难度（in-vitro + 真实世界）、通用与特定里程碑量化；全自动评估 | 全自动 agent 端到端 SR 仅 21%（简单任务 27%、真实仅 1 个）；辅助 agent 64%；暴露任务失败 | https://arxiv.org/abs/2410.03225 · https://github.com/lucagioacchini/auto-pen-bench |
| **Towards Automated Penetration Testing** → 常被称 PentestBench (Isozaki et al.) | 基准 / 评测 | 提出开放、自动化的端到端渗透基准；用 PentestGPT 评测 GPT-4o / LLaMA3.1-405B；消融指导框架改进；配套 AI-Pentest-Benchmark 仓库 | 结论是"目前均难全自动完成，即使加最小人工辅助"；基准本身仍在演进 | https://arxiv.org/abs/2410.17141 · https://github.com/isamu-isozaki/AI-Pentest-Benchmark |
| **CVE-Bench** (UIUC Kang Lab) | 基准 / 数据集 | 评测 AI agent 利用真实 Web 应用 CVE 的能力；覆盖多漏洞类别与真实历史漏洞；衡量安全利用而非修复 | 聚焦 Web 应用单点利用，不覆盖内网横移/权限提升全链路 | https://arxiv.org/abs/2503.17332 · https://github.com/uiuc-kang-lab/cve-bench |
| **CyberSecEval (Purple Llama, Meta)** | 基准 / 评测套件 | 安全编码与攻击能力基准；CyberSecEval 3 扩展 8 类风险；被广泛引为安全评测基线 | 偏"编码助手安全评估"，面向 LLM 能力/风险度量而非完整渗透；有批评性再审视（2411.08813） | https://arxiv.org/abs/2312.04724 · https://arxiv.org/abs/2408.01605 · https://arxiv.org/abs/2411.08813 |
| **RapidPen** (SecDevLab) | 论文 / 开源框架 | 全自动 IP→Shell：ReAct 任务规划 + 检索增强利用知识库 + 命令生成/执行反馈；HTB 目标 200-400s 拿 shell，单次成本约 $0.3–0.6，复用成功案例 60% SR | 依赖历史成功利用样本（success-case 数据）；成本/成功率有前提条件 | https://arxiv.org/abs/2502.16730 · https://secdevlab.com/rapidpen |
| **xOffense** | 论文 / 开源框架 | 多智能体（侦察/扫描/利用 + 编排层）+ 领域微调 Qwen3-32B 做规划；在 AutoPenBench 与 AI-Pentest-Benchmark 上子任务完成率 79.17%，超越 VulnBot/PentestGPT | 基于领域微调中规模模型，基座能力受限于 32B；多智能体编排复杂度高 | https://arxiv.org/abs/2509.13021 |
| **APT-Agent** | 论文 / 框架 | 混合纠错模块修复幻觉命令 + 命令级记忆保持长上下文；Metasploitable2 七服务端到端利用成功率 84.29%（对照 PentestGPT 18.57%） | 基于 Metasploitable2 单一环境，真实内网覆盖有限 | https://arxiv.org/abs/2605.24949 |
| **ZERO-APT** | 论文 / 框架 | 攻-防-判三方框架：LLM Defender 读 Sysmon 实时检测；计划/执行分离 + ReAct 多维度反馈 + 动作库硬约束，提升因果一致性；Judge 生成 CTI 审计报告 | 面向 Windows 后利用原型；防守配置仅 3 种；LLM 推理仍为核心不确定点 | https://arxiv.org/abs/2606.05567 |
| **CHECKMATE / PEP 范式** (Wang 等) | 论文 | Planner-Executor-Perceptor 综述框架；结论：Claude Code/Sonnet 4.5 显著超现有系统；CHECKMATE 用经典规划外部"大脑"强化，成功率提升 20%+，时间与成本降 50%+ | 外部规划依赖结构化任务空间；对开放式/未知目标规划仍有挑战 | https://arxiv.org/abs/2512.11143 |
| **Excalibur** (Deng/Qiu 系列) | 论文 | 难度感知规划：Type A(工程性能力gap)靠强工具层+工具接口；Type B(规划/状态管理)靠 Task Difficulty Assessment(TDA)四维评估 + 证据引导攻击树搜索(EGATS)；CTF 任务完成达 91%，GOAD AD 5 主机拿下 4 | 难度估计需历史/证据特征支撑；前沿模型依赖（要求 frontier models） | https://arxiv.org/abs/2602.17622 |
| **Red-MIRROR** | 论文 / 框架 | 多智能体（规划器+执行器）经 RAG(govern)+共享循环记忆(SRMM)+双相反思应对复杂 Web 利用；XBOW 基准成功率 86.0%，子任务完成率 93.99%（超越 PentestAgent 50%、AutoPT 46%、VulnBot 6%） | 面向 Web 漏洞利用，跨领域适用性待验证 | https://arxiv.org/abs/2603.14985（对应正文中所述工作，编号按抓取数据展示） |
| **Cochise** (andreashappe) | 开源基准实验台 | 630 行 Python 参考实现，Planner-Executor 架构，SSH 驱动；附带 replay/analyze 工具与 GOAD 轨迹日志语料；非 SOTA，而是可复用实验基础设施 | 定位为实验台而非高能力 agent；SSH 依赖跳板机 | https://arxiv.org/abs/2605.11671 · https://github.com/andreashappe/cochise |
| **CTFusion** | 基准 | CTF 场景下评测 LLM agent 能力（发现/利用/后利用） | CTF 与真实网络差距大，安全措施不设防 | https://arxiv.org/abs/2605.11504 |
| **AgentPoison** | 论文（红队LLM） | 针对 LLM agent 的记忆/知识库投毒做红队，提示 agent 被引出恶意/越权行为 | 属 LLM agent 红队而非渗透测试本体 | https://arxiv.org/abs/2407.12784 |
| **Towards Effective Offensive Security LLM Agents** | 评测 | 系统研究超参与调优、LLM-as-Judge 评估、网络安全 agent 效果 | 方法与结论均处研究早期 | https://arxiv.org/abs/2508.05674 |
| **Decoupling Recon&Exploitation** (2506.25332) | 论文 | 分离式两阶段评估：给定准确漏洞上下文时 agent 功能成功率可达 90%，但自主侦察阶段目标漏洞召回率仅约 50%；揭示"多智能体利于反序列化长链、单块利于短链注入、图驱动利于跨会话访问控制" | 仅 Web 漏洞集合；说明侦察是主要瓶颈而非利用 | https://arxiv.org/abs/2606.25332 |
| **The Role of AI in Modern Pentesting**（综述） | 系统综述 | 58 篇研究：AI 渗透仍早期，77% 集中在 RL（非 LLM），主要覆盖发现/利用阶段，侦察与后利用薄弱；LLM 应用待深挖 | 综述本身而非新系统 | https://arxiv.org/abs/2512.12326 |

---

## 三、代表性开源渗透 Agent 框架清单（GitHub 实测，含 star）

| 项目 | 类型 | 能力要点 | 局限 | 来源链接 |
|---|---|---|---|---|
| **GreyDGL/PentestGPT** | 开源框架 | 最成熟/最新 Agentic 渗透框架之一，约 14.8k star；LLM 驱动自动化 Web/CTF 渗透 | 端到端全自动成功率低，需较强基座模型 | https://github.com/GreyDGL/PentestGPT |
| **PurpleAILAB/Decepticon** | 开源 agent | 自主红队/攻击 agent，约 5k star；感知-推理-规划-执行闭环 | 社区驱动，稳定性/边界未工业验证 | https://github.com/PurpleAILAB/Decepticon |
| **GH05TCREW/pentestagent** | 开源框架 | 黑盒安全测试 agent，支持漏洞赏金、红队、渗透工作流，约 2.9k star | 商业化导向，能力验证依赖社区用例 | https://github.com/GH05TCREW/pentestagent |
| **CyberStrikeus/CyberStrike** | 开源装具/harness | 开源 AI 进攻性安全 harness：13+ 自治 agent、150+ LLM provider、5,300+ 模型、7,600+ 攻击技能、56+ 工具、176+ MCP 工具，约 1.8k star | 体量大、上手门槛高；技能质量良莠不齐 | https://github.com/CyberStrikeus/CyberStrike |
| **scadastrangelove/awesome-ai-security-tools** | 清单 | 精选 AI 安全/辅助网安工具（渗透 agent、自动分诊、agent 安全、AIS 供应链等），约 1k star | 清单非工具 | https://github.com/scadastrangelove/awesome-ai-security-tools |
| **chainreactors/aiscan** | 开源工具 | AI 驱动类 pi 网安 agent，单二进制，覆盖渗透/红队/漏洞赏金，约 245 star | 新项目，生态待成熟 | https://github.com/chainreactors/aiscan |
| **Yeti-791/Awesome-Offensive-AI-Agentic-Landscape** | 聚合清单 | 汇总开源项目/论文/能力基准/国内外商业方案（AI 渗透、LLM 红队、自治攻击），约 205 star | 清单型，需按条目回溯 | https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape |
| **Mr-Infect/AI-penetration-testing** | 开源工具包 | AI/ML/LLM 渗透测试与对抗性 ML 资源聚合 | 内容质量参差，部分为资源聚合 | https://github.com/Mr-Infect/AI-penetration-testing |
| **cdxiaodong/cain-agent** | 开源框架 | 真实世界授权评估型 AI 渗透工程师，内置 AWS/Azure/GCP + 阿里/腾讯/华为云模块，基于 Claude Agent SDK | 云厂商专项，授权依赖强 | https://github.com/cdxiaodong/cain-agent |
| **fr33d3m0n/threat-modeling** | 开源 skill/工具 | AI 原生自动化软件风险分析：威胁建模/安全测试/渗透/合规，Code-First | 偏建模与静态分析 | https://github.com/fr33d3m0n/threat-modeling |
| **antoninoLorenzo/AI-OPS** | 开源助手 | 基于开源 LLM 的渗透测试 AI 助手 | 开源 LLM 能力上限低 | https://github.com/antoninoLorenzo/AI-OPS |
| **CyberSunil/LLMVault** | 开源靶场 | 故意易受攻击的 OWASP LLM Top10 训练平台，含注入/RAG/agent 安全/GenAI 渗透 | 面向 LLM app 安全而非传统渗透 | https://github.com/CyberSunil/LLMVault |
| **crazyMarky/pentest-skills** | 开源 skills | 自然语言驱动的专业渗透测试技能集（面向 Claude Code/Codex/Gemini CLI/OpenCode） | 依赖宿主 CLI agent 能力 | https://github.com/crazyMarky/pentest-skills |

---

## 四、基准评测侧重点对比（如何衡量 agent 渗透能力）

| 基准 | 场景 | 衡量维度 | 关键发现 | 链接 |
|---|---|---|---|---|
| CVE-Bench | 真实 Web CVE 利用 | 能否真正利用真实漏洞 | 说明 agent 已具备自动化真实利用能力，也带来滥用风险 | https://github.com/uiuc-kang-lab/cve-bench |
| AutoPenBench | 33 个分层靶机（含真实） | 里程碑达成/端到端成功率 | 全自动 21%，半自动加人 64% | https://github.com/lucagioacchini/auto-pen-bench |
| AI-Pentest-Benchmark | 渗透评测 | PentestGPT 基座/消融 | 学界用它做横向对比 | https://github.com/isamu-isozaki/AI-Pentest-Benchmark |
| CyberSecEval 1/3 | 编码助手安全 | 安全编码 + 攻击能力 / 8 类风险 | LLM 安全能力与风险的标准化度量 | https://arxiv.org/abs/2312.04724 |
| HackSynth/VMS CTF 集 | PicoCTF + OverTheWire ~200 题 | 分难度任务通过率 | GPT-4o 最佳 | https://github.com/aielte-research/HackSynth |
| CTFusion | CTF | 发现/利用/后利用 | CTF 基准对比 | https://arxiv.org/abs/2605.11504 |
| ZERO-APT | Windows AD 对抗 | 智能防守下攻击成功率/因果一致性/可审计 | 防守下 79% 攻击成功率 | https://arxiv.org/abs/2606.05567 |
| PentestEval | 6 阶段 346 任务 | 阶段级能力 | 端到端仅 31%；自治 agent 几乎全败 | https://arxiv.org/abs/2512.14233 |

---

## 五、能力边界与失败模式（跨论文一致结论）

1. **失败模式分两类**（Excalibur 2602.17622 归纳）：
   - **Type A**：能力空白（缺工具、提示词不当）→ 工程可快速修复。
   - **Type B**：规划/状态管理缺陷 → 根因是"缺乏任务难度实时评估"，导致时间花在低价值分支、上下文过早耗尽；该类对底层 LLM 几乎不变。
2. **侦察是主要瓶颈**：分离式评测（2606.25332）给出利用阶段成功率可到 90%，但自主侦察的目标漏洞召回仅约 50%（信息摘取的 telemetry 解析失败为主因）。
3. **无法维持长程规划/复杂推理/专业工具利用**（CHECKMATE 综述结论）——单靠模型缩放无法根治（Excalibur 亦证）。
4. **幻觉命令**：APT-Agent 引入纠错模块直接用幻觉命令恢复方案佐证其普遍性。
5. **评测结果依赖基座模型**：Claude Code/Sonnet4.5、GPT-4o 大幅领先早期 PentestGPT 系；开源/中规模模型（Qwen3-32B-ft）差距明显，但通过领域微调+多智能体可缩小。
6. **安全/法律边界**：基准均已放在受控靶场/容器；多篇强调 dual-use（双刃剑）风险、授权前提与责任归属（2507.00829）。

---

## 六、对 t3 报告原料的补充要点（供 analyst）

- 若要在本机 DSH 环境做**受控渗透实验**，最易落地的开源组合：**GreyDGL/PentestGPT**（社区大、起步低）+ **CVE-Bench/AutoPenBench 类靶场**（有标准评估）+ **HackSynth/Cochise**（轻量实验底座、日志可回放）。优先选有外部规划/难度感知的新架构（CHECKMATE/PEP、Excalibur 思路）规避 Type B 失败。
- **不要直接在真实系统运行**，全部限定在本地 CTF 靶机或隔离容器（对齐 OpenAI/Meta 安全实践）。
- 评测要同时看"端到端成功率"与"阶段成功率"，否则会被利用阶段的高分误导。
