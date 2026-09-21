# DSH 插件化与内核旁路治理（方案评估）

> 建档：2026-09-21　　起因：`docs/DSH宿主实测记录.md` 第十节的真机实测发现
> ——「内核工具装上了，但模型用宿主 shell 把活干完了」。
> 本文回答一个问题：**这件事该怎么解，要不要把 Proteus 做成一个完整的 DSH 插件（bundle）？**

---

## 一、先定性：这不是"模型不听话"

实测里模型给出的拒绝理由逐条成立（原文见 `DSH宿主实测记录.md` 10.4）：

1. **任务纪律冲突**——轻量侦察任务不许发载荷/爆破，而内核的 `nuclei_scan` /
   `sqlmap_auto` / `ffuf_fuzz` / `gobuster_dir` / `fscan_scan` / `pf_*` 本质是
   主动扫描器；
2. **链路到不了目标**——`pentest_run` / chameleon 系走**远端采集桥/代理**，
   对 `127.0.0.1` 回环目标不成立；
3. **证据精度不足**——任务要"状态码 + 原始响应头 + 可重放证据"，内核单点工具
   （`http_probe` / `robots_fetch`）的固定输出格式给不了；
4. 宿主 `pwsh` 一条命令即可完成，且统一节流、统一判读，更可审计。

**所以问题拆成三层**，缺一层都治不好：

| 层 | 问题 | 现状 |
|---|---|---|
| L1 能力 | 内核在"本机回环 + 轻量侦察"场景**没有比 shell 更好的工具** | 缺原始响应类工具；远端桥工具到不了回环 |
| L2 机制 | 内核是否被使用**全靠模型自觉**；宿主 shell 是万能替代品 | 只有 persona 软约束（实测已被合理绕过） |
| L3 审计 | 即使走了宿主工具，**证据链/记忆/技能全部空转** | 内核完全看不见会话里发生了什么 |

L2 是硬规则 1（约束必须机制性生效）的直接违反；L3 让"结论可机验"这一内核卖点
在 DSH 路径上归零。

---

## 二、能力边界：preset 行 vs 完整插件（决定形态的事实）

DSH 的两层组合（源码调研结论，证据见括号）：

| 能力 | agent-preset 行（我们现在用的） | host 平面 bundle 插件 |
|---|---|---|
| 注册工具 | ✅（可写 `name:` 包或相对路径的本地插件行） | ✅ `ctx.tools.register` |
| **按工具名拦截/裁决** | ❌ YAML 无此机制；preset 无 patch 语义（`agent-presets/README.md:180`） | ✅ `ctx.tools.restrict({allow,deny})`（须 scoped，`core/tools/src/index.ts:1077`）+ `tools/pre-execute` 逐调用 allow/deny/cancel/**ask**（`:146`） |
| **改写工具结果 / 阻断** | ❌ | ✅ `tools/post-execute` `accept/block`（`:169`） |
| 包装执行生命周期（超时/指标） | ❌ | ✅ `tools/execute` wrapper（`guard/timeout-policy` 即此形态） |
| 订阅工具与会话事件 | ❌ | ✅ `session/event`、`tool/call`、`tool/result`（`core/session/src/types.ts:341,355`） |
| 加 system prompt 段 | ✅（persona 行） | ✅ `ctx.systemPrompt.section`（`core/system-prompt/src/index.ts:455`） |
| 拥有策略/沙箱/审批栈 | ❌ **刻意禁止**：preset 不能放宽自己的 confinement（`presets/cordis/.../SKILL.md:100-102`） | ✅ 可提供/替换 host 服务、注册沙箱 provider、充当 approval answerer |
| 网络出口策略 | ❌ | ⚠️ **没有官方 egress 词汇**：沙箱只表达文件效果（`sandbox/README.md:167`）——但可以在 `pre-execute` 里按工具名/参数**自建**策略 |
| 破坏性风险 | 低（配置层） | 高：宿主代码**进程内执行、在沙箱之外**（`plugin-manager/README.md:31`） |
| 版本耦合 | 中（composition 是某一版 fork，升级会失效——本仓刚因此静默消失过一次） | 中高（alpha 且包频繁改名：`AGENTS.md:7`，`docs/rescope.md`） |

**两个关键可行性发现**：

1. **`tools/pre-execute` 能读到参数**（只是不能改写）。所以"某条 shell 命令是不是
   在对目标发请求"是可以判定的 → **"目标动作必须走内核"可以被机制化执行**，
   而不必禁用整个 shell。
2. **`tools/post-execute` + `session/event` 能看到每一次工具调用**（不管是谁家工具）。
   所以"模型绕过内核"这件事本身可以被**记录**——把宿主工具的调用也写进内核证据链，
   L3 就有了不依赖模型自觉的解法。

---

## 三、三个方案

### 方案 A（仅内核侧）：补齐"原始证据"工具，让内核回到牌桌上

- 新增本地直连、**返回原始响应**的探测工具（状态行 + 完整响应头 + 正文片段 +
  耗时，`http_raw` 类），并给现有 `http_probe` 加"原始头"开关；
- 让 `pentest_run` / chameleon 支持**直连模式**（不走远端桥），或至少让内核在
  工具描述里写明"到不了回环目标"，避免模型误判；
- 成本：1~2 天，独立于宿主形态，评测侧同时受益（agent-lab 判定也要原始头）。
- 局限：**只治 L1**。模型仍可能选 shell（L2），审计仍断（L3）。

### 方案 B（仅宿主侧）：preset 里禁掉宿主 shell 行

- 事实：我们的 preset fork 自 standard，**主动重新声明了** `tool-pwsh` / `tool-bash`
  行（web 产品的 host patch 本来是禁的），所以会话里有 shell；把这些行
  `disabled: true` 就等于机制性切断替代品。
- 代价：本地解压/写报告/跑脚本也没了（preset 的初始设计正需要它们），
  且没了 shell 模型只能转向内核工具——**在 L1 修好之前这么做，会话体验会变差**。
- 判定：**在 L1 完成前不要做**；完成后可作为"某些模式（如 ctf）"的收紧手段。

### 方案 C（宿主侧，完整插件）：`dsh-proteus` bundle 插件

把内核从"被调用的 MCP server"升级为"拥有宿主平面机制的一等插件"，做三件事：

1. **策略裁决**（治 L2）：注册 `tools/pre-execute` listener——
   - 识别"对目标发请求"的宿主工具调用（按工具名 + 参数模式，如 shell 命令里出现
     目标白名单内的 host/URL）；
   - 按模式裁决：`ask`（人工确认）/ `deny`（附"请改用 `mcp__proteus__*`，理由…"）/
     `allow`（本地操作放行）；
   - 这一步是**机制性的**：模型可以继续用 shell，但绕不过裁决。
2. **证据链固化**（治 L3，价值最高）：订阅 `session/event` 的 `tool/call` 与
   `tool/result`，把**会话里发生的每一次工具调用**（无论宿主工具还是内核工具）
   追加进 `penagent/evidence.py` 的链式哈希证据链；
   - 于是"结论可机验"在旁路场景也成立；
   - 顺带解决"报告不可机验、无法复用评测判定"的问题（agent-lab 的判定口径可直接
     吃到这些记录）。
3. **提示词与工具面**（治 L2 的另一半）：用 `ctx.systemPrompt.section` 写"目标动作
   优先走内核 + 三种允许例外"（与 `prompts/dsh-persona.md` 同源，但落在 host 平面、
   优先级更硬）；可选地 `restrict` 掉与内核重复且更危险的宿主能力。

- 成本：需以 npm 包 + `dsh.bundle.patch` 形式安装进 profile（`dsh plugin --profile web add`），
  要跟随 DSH 版本演进；宿主代码在沙箱外进程内执行，安全模型要重新说明。
- 局限：仍**没有网络 egress 官方词汇**——策略只能在工具层做，不是内核级网络管控。

---

## 三之补：实施状态（2026-09-21 当晚）

| 步骤 | 状态 | 交付物 | 真机证据 |
|---|---|---|---|
| 第一步 · 内核补原始证据工具 | **已实施** | `penagent/builtin_tools.py` 的 `http_raw`（状态行 + 完整响应头 + 正文片段 + 耗时；不跟随重定向；4xx/5xx 按响应返回） | 真实靶场实测：`/sitemap.xml` 与 `/` 同为 `200 text/html len=9903`（SPA 兜底一眼可分），`/api/Products` 为 `application/json len=16026`；内核 MCP 工具数 40 → **41** |
| 第二步 · 证据链固化（只读观测） | **已实施** | 宿主 bundle `dsh/proteus-bridge`（订阅 `session/event` → spool）+ 内核导入器 `penagent/dsh_bridge.py` + CLI `python -m penagent dsh-sync` | 真实 headless 会话跑完 → spool 2 行 → 入链 1 条 `tool='pwsh' · ok=True · args={'command': 'echo bridge-v2-ok'}`，链校验 OK；DSH web 侧 `--dump-config` 可见 `# == dsh-proteus-bridge` 层 |
| 第三步 · `pre-execute` 目标动作裁决 | **已实施**（2026-09-21，用户拍板：接受宿主进程内执行的前提 + 默认档位 `ask`） | 同 bundle 的 `tools/pre-execute`：只拦"对目标发请求的宿主 shell 命令"（网络动词识别 + 目标提取），越界目标与白名单内目标分别给不同理由；`mode: ask / deny / off` 可切 | 真机（headless）：模型用 `pwsh curl http://127.0.0.1:3000/` → **被 ask 拦下** → 该 profile 无审批应答者（fail-closed）→ `requires approval, but …`；模型重试仍被拦、转而用 `web_fetch` 又被 DSH 自己的 provider 拦（`WEB_BLOCKED_URL`），最后**如实说明没拿到输出**、未编造结果。链上一共留痕 5 条：2×裁决（observation）+ 2×失败的 tool_call + 1×web_fetch 拒绝 |

**形态选择的落地结论**：第二步本可以塞进 preset 行里做，但按研究结论它拿不到 `session/event` 的订阅面——**必须是 host 平面 bundle**。这也是"要不要做成完整插件"这个问题的实际答案：**该做成插件的那部分，就是"机制与审计"**（事件订阅、裁决、策略）；"提供工具"那部分继续留在 MCP + preset 行即可（成本最低、与 DSH 版本耦合最小）。

### 实施中踩到的两个形状陷阱（都靠真机验证抓出来）

1. **`tool/result` 的 `callId` 不在事件顶层**（那是 `tool/call` 的字段），而在
   `message.source.callId`（`@deepseek-ai/dsh-llm` 的 `message.ts`：
   `ToolMessageSource = { kind: 'tool', callId }`）。第一版插件取不到 → 结果行
   callId 全空 → 配对失败、记录丢了工具名与参数。
   → 插件改为三级探测（顶层 → `message.source` → block），导入器再加
   `(turn, step)` 兜底配对，历史 spool 与形状变化都能吞下。
2. **未配对的调用不能立即记账**：第一版把"只有调用没有结果"也入链，结果
   随后到达时会留下同一次调用的两条记录——看着可审计、实际对不上。
   → 改为**挂起并跨导入持久化**（状态文件里存 pending），`--flush-open`
   才显式冲刷（会话已结束、结果永不来的场景）。

### 用法（本机已装好）

```bash
# 宿主侧：把桥装进目标 profile（会自动追加 dsh.bundle 层）
dsh plugin --profile web add <REPO>/dsh/proteus-bridge
dsh plugin --profile headless add <REPO>/dsh/proteus-bridge   # 无 UI 验证用
# 装完重启 DSH 进程（bundle 层在启动时合成）

# 内核侧：把 spool 并入独立证据链（默认 data/dsh-chain.jsonl，不动内核任务链）
python -m penagent dsh-sync --data data
python -m penagent dsh-sync --data data --flush-open    # 会话结束后冲刷未配对调用
```

> **web profile 的 pnpm 版本陷阱**：本机 `~/.dsh/profiles/web` 的 node_modules
> 由另一个 pnpm 大版本安装，`dsh plugin add` 直接失败（store 版本不匹配）。
> 本次按该命令的等价做法手工登记：备份 `package.json` → 加 `link:` 依赖 →
> `bundles` 追加 `dsh-proteus-bridge` → 建同名符号链接。备份文件留在
> `~/.dsh/profiles/web/package.json.bak-proteus-bridge-*`。

## 四、建议：分三步走，顺序不能反

1. **先做 A**（内核侧原始证据工具 + 直连/明示链路限制）——它是前提：L1 不修，
   任何"强制走内核"的机制都会把会话推向更差的工具。
2. **再做 C 的第 2 件事（证据链固化）**——投入产出比最高、风险最低：
   只读事件、不拦截执行，就能把"Dsh 会话里的一切动作"纳入可机验范围；
   同时它给评测（agent-lab）提供真实会话的判定素材。
3. **最后做 C 的第 1 件事（pre-execute 裁决）**——在 L1 修好、且证据链固化跑通之后
   再收紧；先以 `ask` 而非 `deny` 上线，观察模型的绕过率与理由，再决定是否收紧到
   `deny`。C 的第 3 件事（提示词落 host 平面）与第 1 件同批做。

**不推荐**：B 单独使用（体验降级）；C 抢在 A 前面做（强制用不好用的工具）。

**决策点（需要拍板）**：

- ① 是否接受"宿主进程内执行插件、在沙箱之外"这一安全前提（C 的必要条件）；
- ② 证据链固化用**独立链**（`data/dsh-chain.jsonl`）还是并入现有 `data/chain.jsonl`；
- ③ 目标动作裁决的默认档位：`ask`（推荐先跑一段时间）还是直接 `deny`。

---

## 五、与现有资产的关系

- **不改内核契约**：`penagent/evidence.py` 的链式哈希是底线（硬规则 2），插件只是
  多一个写入方（append-only，不触碰校验逻辑）；
- **与评测闭环衔接**：证据链固化后，agent-lab 的 `score_from_evidence` 可以直接判定
  DSH 会话产出的记录，宿主路径与自有 CLI 路径的评测口径得以统一；
- **与 persona 的关系**：`prompts/dsh-persona.md` 保留"优先 + 三种例外"（软约束，
  面向模型）；方案 C 把同一条规则落到 `pre-execute`（硬约束，面向机制）——两者同源，
  一个讲道理、一个踩刹车。

### 第三步的语义细节（真机跑出来的两条必须记下）

1. **`ask` 在无人值守路径上等于拒绝**：headless（以及任何没有审批应答者的 profile）
   遇到 `ask` 会 fail-closed —— 实测返回 `Error: tool "pwsh" requires approval, but
   …`。这符合"没人能批准时宁可不放行"的语义，但**要意识到默认档位在不同入口的
   实际效果不同**：web 会话里 `ask` 是弹审批卡片（可"允许一次"），headless 里
   就是拒绝。自动化场景若想放行，得先接审批应答者，或把 `mode` 调成 `deny`
   （显式拒绝、理由更清楚）——不要以为"默认 ask 就等于宽松"。
2. **裁决不惩罚"本地动作"**：`echo`、文件读写、跑本地脚本一律放行（实测的
   `echo bridge-v2-ok` 未被拦），只有"网络动词 + 目标"同时命中才介入——否则
   会退化成"什么都要批"的噪音门。

### 裁决层的边界（诚实声明）

- 只覆盖**宿主 shell 工具**（`shellTools: [pwsh, bash]`，可配）。模型若改用其它
  能发网络请求的宿主工具（如 `web_fetch`），本层不管——实测那次由 DSH 自身的
  web provider 拒绝（`WEB_BLOCKED_URL`，provider 内建 SSRF 防护），属另一道闸。
- 目标识别是**启发式**（URL/`--host`/`-u` 参数/裸 IP），命令里做变量拼接或
  编码绕过时可能认不出——所以它是"提高旁路成本 + 留痕"，不是密不透风的 egress
  管控（DSH 没有 egress 词汇，这点在前文能力边界里已写明）。
- `mcp__proteus__*` 一律放行：内核闸门已经管过了，宿主层不重复设卡。

