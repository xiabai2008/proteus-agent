# AI 网安 Agent 渗透测试现状调研报告

> 调研方式：队长直连 HTTP 一手数据（arXiv API + GitHub API + 社区生态全景清单），数据时点 2026-08。原计划由 AgentTeams 两位研究员执行，因 DeepSeek 账户余额不足（Insufficient Balance）失败，由队长接管完成。

## 一、结论速览

- **学术与开源**：2023 年 PentestGPT 起步，2024 年证明 LLM agent 可自主利用 1-day/0-day 漏洞，2025 年多智能体协作 + AIxCC 决赛，2026 年进入"实证质疑 + 商业化"阶段。开源框架大多停留在"半自动 + 靶场验证"，真实环境成功率仍低。
- **商业产品**：全球已形成 30+ 家产品，国外 XBOW/Pentera/Horizon3/Anthropic Mythos 领跑（估值均超 $1B 级），国内绿盟/奇安信/360/阿里云等 10 家跟进。竞争点从"能不能跑"转向"误报率 + 真实漏洞验证 + 合规交付"。
- **能力边界**：基准成功率普遍个位数到 30%；高分数可能主要来自模型本体而非架构（Cochise、Baselines Before Architecture 的怀疑论研究）；目标欺骗可让 agent 产生误报（ATOBench）。
- **落地建议**：个人/团队自建首选「开源 agent + 靶场基准 + MCP 工具链」组合，商业采购看真实漏洞验证与误报控制。

## 二、学术与开源现状（时间线）

### 2023 · 探索期
- **PentestGPT**（GreyDGL，arXiv:2308.06782，GitHub 14.8k★）— 首个 LLM 渗透测试框架：推理模块 + 解析模块 + 任务生成模块，交互式引导渗透。
- InterCode-CTF 等早期 CTF agent。

### 2024 · 基础与基准建立（Fang 三部曲）
- **LLM Agents can Autonomously Hack Websites**（arXiv:2402.06664）
- **LLM Agents can Autonomously Exploit One-day Vulnerabilities**（arXiv:2404.08144）— 已知 CVE → 自动利用
- **Teams of LLM Agents can Exploit Zero-Day Vulnerabilities**（arXiv:2406.01637）— 多 agent 协作 0day 利用（UIUC Richard Fang 团队）
- **PentestAgent**（arXiv:2411.05185）— 多 agent 自动化渗透流水线
- **HackSynth**（arXiv:2412.01778）— Planner + Summarizer 双模块 + 评测框架
- **Towards Automated Penetration Testing: LLM Benchmark**（arXiv:2410.17141）— 引入渗透基准与改进
- **CyberSecEval**（Meta Purple Llama，arXiv:2312.04724 / v3: 2408.01605）— LLM 网络安全能力/风险基准
- 基准族：Cybench、NYU CTF Bench、AutoPenBench、EnIGMA

### 2025 · 多智能体协作 + 真实漏洞评测 + AIxCC
- **VulnBot**（arXiv:2501.13411）— 多 agent 协作渗透框架
- **CVE-Bench**（UIUC Kang Lab，arXiv:2503.17332，ICML 2025）— 真实世界 CVE 利用基准
- **On the Surprising Efficacy of LLMs for Penetration-Testing**（arXiv:2507.00829）— 综述性批判考察
- **VMS**（arXiv:2507.21113）、**Guided Reasoning + 结构化攻击树**（arXiv:2509.07939）
- **DARPA AIxCC 决赛**（2025-08）：ATLANTIS（冠军，arXiv:2509.14589）、FuzzingBrain（arXiv:2509.07225）等 4 队系统论文；LLMxCPG（USENIX 2025）
- 人评基准：**VADER**（arXiv:2505.19395）、CASTLE、eyeballvul、AI Cyber Risk Benchmark（arXiv:2410.21939）

### 2026 · 实证质疑 + 商业化加速
- **PEP：Planner-Executor-Perceptor 范式**（arXiv:2512.11143）
- **PentestEval**（arXiv:2512.14233）— 模块化分阶段基准（侦察/利用/后渗透分阶段计分）
- **Cochise**（arXiv:2605.11671）— 参考 harness，量化"架构增益 vs 简单 agent"
- **Baselines Before Architecture**（arXiv:2607.13085）— 高基准分数可能主要来自 backbone 模型
- **ATOBench**（arXiv:2608.12996）— 目标系统欺骗响应会误导 agent 的漏洞验证（误报根源）
- **FuzzingBrain V2**（arXiv:2605.21779）— OSS-Fuzz 上实战挖出真实 0day
- 机器人/OT 多 agent 工作流（arXiv:2603.24221）

### 开源项目精选（GitHub 实时 stars）
| 项目 | Stars | 定位 |
|---|---|---|
| rapid7/metasploit-framework | 38.8k | 利用框架（agent 常调用的底层工具） |
| projectdiscovery/nuclei | 30.5k | 模板化漏洞扫描器 |
| GreyDGL/PentestGPT | 14.8k | LLM 渗透框架鼻祖 |
| 0x4m4/hexstrike-ai | 11.0k | **MCP server**：让 Claude/GPT 等 agent 自主渗透 |
| PurpleAILAB/Decepticon | 5.1k | 自主红队 hacking agent |
| sooryathejas/METATRON | 3.4k | 本地 LLM 渗透助手（Parrot OS） |
| GH05TCREW/pentestagent | 2.9k | 黑盒安全测试 agent 框架 |
| oritera/Cairn | 2.3k | 状态空间搜索，渗透验证 |
| CyberStrikeus/CyberStrike | 1.8k | 13+ 自主 agents，150+ LLM providers |
| JoasASantos/NeuroSploit | 1.3k | AI 渗透框架 |
| uber/ADR | 1.4k | 企业 agent 安全观测/基准 |
| ethz-spylab/agentdojo | 744 | LLM agent 攻防评测环境 |
| 0ca/BoxPwnr | 443 | **HTB/TryHackMe 基准框架**（自测首选） |

生态索引：[Yeti-791/Awesome-Offensive-AI-Agentic-Landscape](https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape)（56 开源项目 / 73 论文 / 13 基准 / 32 商业产品）

## 三、商业产品（融资/估值已核查）

### 国外 Top（按融资/估值）
| 产品 | 关键证据 | 定位 |
|---|---|---|
| **Anthropic Claude Mythos** | 万亿估值母公司；Project Glasswing 覆盖 150+ 关键基础设施 | 2026 最受关注 |
| **Pentera AVP** | 融资 $250-314M，估值 $1B，ARR $100M+，1200+ 客户 | 暴露验证平台，持续攻击模拟 |
| **XBOW** | $120M C 轮，估值 $1B+，26 个月独角兽；首个登顶 HackerOne 的 AI | 自主攻击性安全，真实 exploit 验证 |
| **Aikido AI Pentest** | $60M B 轮，估值 $1B | 全栈 AI 渗透 |
| **SPLX** | 2025-11 被 Zscaler 收购 | LLM agent 工作流安全 + 红队 |
| **Horizon3.ai NodeZero** | 融资 $183.5M；24 万+ 次自主渗透，客户含 NSA | "World's Best AI Hacker"，免部署 |
| **RunSybil** | $40M（Khosla），创始人 = OpenAI 首位安全员工 | 自主 Web 渗透，与人协作 |
| **Strix** | 开源 34k★ + 商业化 | 动态运行代码找漏洞 + 真实 PoC |
| **Terra Security** | $30M A 轮 | Agentic AI + Human-in-the-Loop 持续渗透 |
| **Theori Xint** | DARPA AIxCC 季军 | AI 代码审计与渗透 |
| 其他 | Corridor（$25M，ex-CISA）、Veria Labs（CTF 52/52）、Dreadnode（ex-MS AI Red Team）、Mindgard、MindFort、Hacktron、Hex（YC W26）、Harmony、CalypsoAI | 细分场景 |

### 国内
绿盟 AI-PTS（SecLLM + MAS，8.8 万漏洞知识图谱 + 8600 POC）、京东云 AIPTS、360 破阵子、阿里云 Agentic BAS（千问多 agent，2026-07 邀测）、奇安信 AI 加特林、安恒恒脑 3.0 渗透智能体、万径千机（AI+YAK 双引擎）、长亭无锋、斗象蛙池AI、悬镜灵脉 PTE。

## 四、能力边界与风险

1. **真实环境成功率仍低**：基准普遍个位数～30%；CVE-Bench 等真实漏洞评测远低于靶场表现。
2. **架构增益存疑**：Cochise / Baselines Before Architecture 表明高分数可能主要来自 backbone 模型，套壳架构贡献被高估。
3. **误报与欺骗**：ATOBench 证实目标系统的欺骗性响应可误导 agent 的漏洞验证——自主渗透的误报是商业化的核心痛点。
4. **安全与合规边界**：未授权渗透违法；agent 自主性越强，越权/破坏面越大；目标数据进入第三方 LLM 有泄露风险；蜜罐与对抗性防御会污染 agent 判断。
5. **双刃剑**：攻击者同样在利用这些能力，防御侧需关注。

## 五、选型建议

- **企业红队/生产验证**：XBOW / Pentera / Horizon3 NodeZero（国外）；绿盟 AI-PTS / 阿里云 Agentic BAS（国内合规）
- **Web 应用专项**：RunSybil、Aikido
- **代码审计 + AI 风险**：Theori Xint、SPLX、Mindgard
- **个人研究者/预算敏感**：PentestGPT + BoxPwnr + HTB 靶场 + hexstrike-ai（MCP 接入自己 agent）；METATRON（纯本地模型）
- **自建评估**：BoxPwnr / PentestEval / CyberSecEval 做能力基线

## 六、本机落地建议（DeepSeek Harness 环境）

1. **只打授权靶场**：HTB / TryHackMe / DVWA / 本地虚拟机——自主渗透严禁触碰未授权目标。
2. **工具链 MCP 化**：通过 MCP server（hexstrike-ai、Burp/Metasploit MCP）把 nuclei/metasploit 挂进 DSH agent 的工具箱，让 agent 编排扫描→验证→报告闭环。
3. **用 BoxPwnr 做基准自测**：量化自己 agent 栈的真实成功率，再决定投入方向。
4. **成本控制**：渗透任务 token 消耗大，成员模型用 flash 级即可（工具调用为主）；账户余额是硬依赖——本次调研即因此受阻。
5. **隔离与审计**：靶场跑在容器/虚拟机；DSH 会话日志天然保留完整审计轨迹，适合复盘 agent 每一步决策。
