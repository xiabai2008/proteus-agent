# DSH 主体化改造方案

> 建档：2026-09-24　　状态：**待实施**（本文只定形态与验收，不含代码）
> 定位变更：**DSH 是主体**（agent 循环 / 上下文压缩 / 计划 / 并行 / UI / 审批 / 沙箱），
> Proteus 是**增强层**（工具面 / 证据链 / 模式闸门 / 技能与记忆 / 评测）。
> 依据：本轮真机实测（2026-09-24）+ 开源对标（PentAGI / PentestGPT / Strix / Cybench / CAI-CSI，现取原文）。
> 前置阅读：`docs/DSH插件化与内核旁路治理.md`、`docs/DSH宿主接入指南.md`、`docs/能力加强路线.md`。

---

## 一、决策记录（2026-09-24 拍板）

| # | 议题 | 决策 |
|---|---|---|
| D1 | 宿主形态 | **双 preset 场景分流**（实装为三个，见 D2） |
| D2 | CTF 细分 | **直接拆** `proteus-ctf-web` / `proteus-ctf-crypto` |
| D3 | 监督层 | **循环检测与救场做成宿主侧插件**（不占内核预算、不写进内核循环） |
| D4 | 授权目标入口 | **会话命令 + 审批卡**（永久授权靠人工命令，一次性放行靠审批卡） |

**形态总览**：打开 DSH → 选择器里选一个 Proteus 入口 → 该场景的全部能力（工具面 / 闸门 /
判定器 / 技能 / 记忆分区）随 preset 一起到位；场景内可用命令做细分切换。

---

## 二、目标形态

### 2.1 三个 preset

| | `proteus-pentest` | `proteus-ctf-web` | `proteus-ctf-crypto` |
|---|---|---|---|
| 默认模式 | `pentest-standard` | `ctf-web` | `ctf-crypto` |
| 场景 | 授权范围内的真实渗透 | Web 类 CTF | Crypto / Misc / RE 类 CTF |
| persona | 授权边界 + 可复现 PoC + 报告交付 | 试错优先 + flag 收口 + 写题解 | 同左（偏数学/脚本） |
| 工具面 | 内置侦察 5 + 外部 CLI 18 + 适配器 + 容器 MCP 6 + seckb / chameleon + 内核高层 | codec 三件 + `python_solve` + `rsactf_attack` + `http_raw` / `http_probe` / `dns_lookup` + 容器 MCP（binwalk / capa / yara / cyberchef / searchsploit）+ chameleon + seckb | codec 三件 + `python_solve` + `rsactf_attack` + `file_type` + binwalk / yara / capa + seckb |
| 明确不含 | CTF 工具（codec / rsactf） | nuclei / sqlmap / fscan / ffuf / gobuster / dalfox / naabu / poxiao / ruoyi / semgrep / sherlock / theHarvester | 同左 + HTTP 类工具 |
| 判定器 | `evidence_chain` + `require_poc` | `flag_regex`（auto_retry 3） | 同左 |
| 预算 | 40 步 / 180 分钟 | 60 步 / 20 分钟 | 60 步 / 20 分钟 |
| 记忆分区 | `pentest-standard` | `ctf-web` | `ctf-crypto` |
| 技能目录 | `data/dsh-skills/pentest-standard` | `data/dsh-skills/ctf-web` | `data/dsh-skills/ctf-crypto` |
| 审批档（host 补丁） | `proteus-standard` | `proteus-ctf` | `proteus-ctf` |
| 评测套件 | `lab` / `agent-lab` / `g07` / `dsh-session` | `ctf`（33 题） | `ctf` |

> 三个 preset 共享同一份内核实现、同一条证据链、同一个审计桥、同一套授权 scope 与内核缺位守卫；
> **差异全部落在配置**（默认模式、persona、工具面、判定器、预算、记忆分区、技能目录、审批档）。

### 2.2 场景内微调

- `/proteus-mode <id>` 保留：`proteus-ctf-web` 会话里切 `ctf-crypto` 做混类题；渗透会话切收紧档。
- 切换后**工具面动态刷新**（内核发 `notifications/tools/list_changed`，DSH mcp-client 原生支持，
  源码见 `@deepseek-ai/dsh-mcp-client/lib/index.js` 的 `listChanged.tools.onChanged → refreshTools()`）。
- 边界（必须写进文档）：内核是**进程级单实例**，`session-mode.json` / `session-scope.json` 是
  进程级文件——**同一 preset 的多个会话并行时会互相影响**。需要真机确认并发行为后再决定是否加锁或分文件。

### 2.3 目录与同步（落点）

仓库（版本受控）：

```
dsh/
├── presets/
│   ├── _shared/                    # 单一实现来源（三个 .mjs，禁止复制三份）
│   │   ├── proteus-persona.mjs
│   │   ├── proteus-tools-policy.mjs
│   │   └── proteus-commands.mjs
│   ├── proteus-pentest/
│   │   ├── agent.cordis.yml
│   │   └── preset.yml
│   ├── proteus-ctf-web/            # 同构
│   └── proteus-ctf-crypto/         # 同构
└── proteus-bridge/                 # host 平面 bundle（不变）
```

安装（`$DSH_HOME/.agent-presets/<id>/`）**必须是真实目录**——发现机制不跟随 reparse point，
链接会让 preset 从选择器里静默消失（2026-09-22 实测）。同步器按 preset 列表逐目录生成：
`_shared/*.mjs` 拷入每个 `<id>/`，与 `<id>/agent.cordis.yml` + `preset.yml` 合成安装副本。

`tools/dsh_install.py` 改造点：`SRC` 单值 → `PRESETS` 列表；`drift()` / `verify_preset()` /
roster 校验 / `--check` 全部按列表循环；`dsh/start-proteus.cmd` 的同步与提示同步改。

---

## 三、开源对标与借鉴清单

> 全部为**现取原文**（2026-09-24）的结论，不是印象。

| 来源 | 事实（原文） | 借鉴项 | 落点 |
|---|---|---|---|
| **PentestGPT v1.0** | 自己不再实现循环，**驱动 Claude Code / Codex**；多阶段流水线（CTF：recon→exploit→walkthrough；渗透：资产发现→漏洞识别→报告），阶段产出喂给下一阶段；会话可存续 | ① 两套阶段化流水线写进 persona；② 会话存档/续跑（`pentest_missions` 已有基础） | `prompts/dsh-persona*.md`、`penagent/report.py` |
| **PentAGI** | ① 监督层：Adviser（同一工具 5 次 / 总调用 10 次介入）+ Planner（先出 3-7 步）+ Reflector（连续 3 次不出工具调用时救场）；② 工具调用硬上限分档（100 / 20）；③ 压缩参数化；④ 可审计层级模型 Flow→Task→SubTask→Action→Artifact→Memory；⑤ Sploitus 漏洞检索 | ① 循环检测与救场（D3 已定为宿主侧插件）；② 调用上限分档；③ 审计层级视图；④ exploit 检索工具 | `dsh/presets/_shared/proteus-supervisor.mjs`（新增）、`penagent/report.py`、`mcp_servers.json` |
| **Strix** | ① **能力以 SKILL.md 技能包分发**（`npx skills add`），任何兼容宿主装上即用；② 产物规范 `report.md` / `vulnerabilities.json` / **`findings.sarif`** / `run.json` + 退出码 0/1/2；③ MCP 接入带 `allowed_tools`；④ `--max-budget` + `scan-mode` 分档；⑤ 内部技能与消费侧技能双层分离 | ① 技能包按 preset 分目录（已定）；② **SARIF 报告 + 退出码**；③ 工具面白名单（已有 `tool_filter`）；④ 双层技能分离 | `penagent/skill_export.py`、`penagent/report.py`、`mcp_servers.json` |
| **Cybench** | 40 题、**子任务分档评分**（unguided / subtask / subtask-guided）；每任务 token 上限；Docker 隔离 | CTF 评测从二值改分档 + 每题预算 | `examples/eval_ctf_solve.py`、`examples/benchmark.py` |
| **CAI / CSI** | ① **多 scaffold 黑板 19/33 Cybench > 最佳单 harness 15/33（+25%）**；② **Jeopardy CTF 已饱和，领域转向 A&D**；③ **AI 安全工具本身是注入面**（四层护栏） | ① 印证"宿主为主体 + 增强层"路线；② CTF 模式定位写清（练手/真实比赛，不追刷分）；③ **目标内容一律不可信**（工具输出标注 + 高影响动作仍需人工） | 本文档第七节、persona、裁决行 |
| **XBOW**（既有） | 验证优先：真尝试利用，不扫到就报 | 保持 `require_poc` | 不变 |

---

## 四、现状错位（实测证据，2026-09-24）

| # | 错位 | 实测证据 |
|---|---|---|
| E1 | **工具面只有执行期拦截，没有可见性裁剪** | `ctf-web` 注册表 32 个工具（含 nuclei/sqlmap/fscan…），`capability.allow` 只在执行时拦 |
| E2 | **CTF 模式的 HTTP 能力被自己的白名单锁死** | `ctf-web` 下 `http_raw` → `allowed=False rule=mode`，理由为"不在 capability.allow `['http_test','browser_auto',…]` 内"；`--authorize=True` 也抬不动（与 `hard_deny` 同类） |
| E3 | **模式只驱动内核，不驱动宿主** | `/proteus-mode` 写 `data/session-mode.json`；宿主裁决行的 `mode` / `targets` 是启动期静态 config |
| E4 | **目标授权硬编码两处** | preset 裁决行 `targets: ['127.0.0.1','localhost']` + MCP 行 `--targets 127.0.0.1,localhost` |
| E5 | **`--discover-mcp` 拖死启动** | Docker 未起时 6 个容器 server 各卡满自己的 timeout（压到 12s 就各 12.0s）；按真实配置 300/60/300/120/300/300 计 ≈ **23 分钟**；根因 `penagent/mcp_client.py` 的 `_read_response` 不感知子进程退出（EOF） |
| E6 | **同步器只认单个 preset** | `tools/dsh_install.py` 的 `SRC` / `drift()` / `verify_preset()` 均为单值 |

> E5 在 D1/D2 之后更严重：**三个 preset = 启动时三个内核进程**（roster 在进程启动时挂载），
> 不修就是 3 × 23 分钟。**E5 是 P0 中的 P0。**

---

## 五、改造清单

### P0 · 地基（不做则"选中即用"是假的）

| # | 动作 | 落点 | 验收判据 |
|---|---|---|---|
| P0-1 | 内核启动变便宜：`_read_response` 感知子进程退出（EOF 即失败）+ `discover_mcp` 全局预算 + 按 server 白名单/懒发现 | `penagent/mcp_client.py`、`penagent/registry.py`、`penagent/cli.py` | Docker 未起时 `--discover-mcp` 启动 ≤ 10s；容器起来后工具照常注册 |
| P0-2 | 修 `ctf-*` 的 `capability.allow` 为**真实注册名** | `modes/ctf-web.yaml`、`modes/ctf-crypto.yaml` | `ctf-web` 下 `http_raw` 可执行；`nuclei_scan` 仍被拒 |
| P0-3 | 工具面按模式裁剪 + `notifications/tools/list_changed` | `penagent/mcp.py`（`_tools_schema` / `_notify`）、`penagent/registry.py` | 切模式后 DSH 工具列表自动刷新；CTF 会话看不到 nuclei |
| P0-4 | 授权入口：`/proteus-scope`（人工命令）写 `data/session-scope.json`；内核与裁决行都从它读 | `dsh/presets/_shared/proteus-commands.mjs`、`penagent/scope.py`（新增）、`penagent/mcp.py`、`proteus-tools-policy.mjs` | 未授权目标一律拒绝且错误信息带授权指引；命令写入后立即生效（无需重启内核） |
| P0-5 | 模式贯通宿主裁决行（运行期读 `session-mode.json`） | `proteus-tools-policy.mjs` | 切到 CTF 模式后，宿主 shell 的目标动作按 CTF 档裁决 |
| P0-6 | 三 preset 实装 + 同步器列表化 | `dsh/presets/**`、`tools/dsh_install.py`、`dsh/start-proteus.cmd` | roster 显示三个 Proteus preset 且全部 `broken=否`；`--check` 逐 preset 校验漂移 |

### P1 · 场景专精

| # | 动作 | 说明 |
|---|---|---|
| P1-1 | 渗透三件套：`session_http`（cookie/token 复用）、`replay_request`（PoC 重放）、`report_gen`（Markdown + SARIF） | 登录后渗透、可复现 PoC、交付物——都是 DSH 侧空白 |
| P1-2 | CTF 工具面补全：pwn（pwntools / checksec 已在镜像）、forensics（volatility）、re（capa / yara / binwalk 已有） | radare2 / Ghidra 维持按需 |
| P1-3 | 工具合并与去重：`port_scan` + `naabu` + `fscan` → 一个；`httpx` + `ehole` → 指纹；适配器与 MCP 声明重名（rayscan）去重 | 减少模型选择负担 |
| P1-4 | 阶段化流水线写进 persona（渗透四阶段 / CTF 四阶段） | 与 PentestGPT 同构 |
| P1-5 | 技能包按模式导出（`skills --export --export-namespace <mode>`） | 三个目录分别挂进对应 preset 的 `customSkillDirs` |

### P2 · 监督与度量

| # | 动作 | 说明 |
|---|---|---|
| P2-1 | 宿主侧监督插件 `proteus-supervisor.mjs`：同一工具+参数重复 N 次 / 总调用超限 → `pre-execute` 返回 deny + 理由（"换思路或说明卡点"），第二次升级为 `ask`；全程入 spool | D3 决策；阈值可配（缺省同工具 5 / 总会话 30） |
| P2-2 | CTF 评测分档（unguided / subtask / subtask-guided）+ 每题 token 预算 | 借 Cybench |
| P2-3 | 审计层级视图（Task / Action / Artifact） | 借 PentAGI；**不改链式哈希底线** |
| P2-4 | 注入护栏：工具返回的目标内容标注不可信；高影响动作保持人工闸门 | 借 CAI 四层护栏的简化版 |

---

## 六、路线图

| 阶段 | 内容 | 验收 | 量级 |
|---|---|---|---|
| **0 · 地基** | P0 六条 | ① Docker 未起时内核 ≤10s 起；② `ctf-web` 下 `http_raw` 可执行；③ 工具面随模式自动刷新；④ 选择器出现三个 Proteus 入口且均不 broken；⑤ 未授权目标被拒并给出授权指引 | 1–2 天 |
| **1 · 场景专精** | P1 | 渗透：登录态扫描 → 重放 PoC → 出报告（含 SARIF）；CTF：web / crypto 各解一道并留 writeup | 2–3 天 |
| **2 · 监督与度量** | P2 | 卡住能被识别并救场（spool 有记录）；CTF 评测出分档分数 | 2–3 天 |

每阶段收尾照旧：**真机 DSH 会话验证 + 全量 pytest 绿 + 一次 commit**（新功能与测试同一提交）。

---

## 六之补、执行记录（2026-09-24，阶段 0 完成）

| # | 交付 | 提交 | 真机证据 |
|---|---|---|---|
| P0-1 | 启动变便宜：EOF 哨兵 + stderr 尾巴 + 全局预算 + 按名子集 | `5e54a33` | Docker 未起时 `--discover-mcp` 启动 **23 分钟 → 6.7s**，注册 49 工具 |
| P0-2 | CTF 模式 allow 改真名 + 家族通配（fnmatch）+ 名单可解析性用例 | `d81f3d7` | `ctf-web`/`ctf-crypto` 下 `http_raw` → `allowed=True`；`nuclei_scan` 仍被拒 |
| P0-3 | 工具面按模式裁剪（列表与执行同一判据）+ `listChanged` 通知 | `bf95551` | `pentest-standard` 33 / `ctf-web` 14 / `ctf-crypto` 11；CTF 工具首次真正可见 |
| P0-4 | 会话授权入口（命令 + 裁决行同源）+ 自我授权防线 | `3d88aba` | 未授权目标被拒且拒因带 `/proteus-scope` 指引；授权后**下一次调用生效**；改写授权文件被拒 |
| P0-5 | 模式贯通宿主裁决行（按会话模式决定档位） | `f2e82f8` | `ctf-web` 下范围内目标动作放行且留痕；越界仍 `ask` |
| P0-6 | 三 preset（模板渲染 + 共享实现单份 + `--session-key` 隔离 + 旧目录迁移） | 本次 | roster 三个均未 broken；会话键隔离实测（A 写 B 读不到） |

阶段 0 验收：全量 **480 passed / 15 skipped**；`dsh_install.py --check` 与
`dsh_compat_check.py` 全绿。**尚未做的**：真机会话（起 web profile 选一个 preset
走一轮"切模式 / 授权 / 裁决"）——阶段 1 开工前先补这一次冒烟。

### 阶段 1 · 场景专精（同日完成）

| # | 交付 | 提交 | 证据 |
|---|---|---|---|
| P1-1 | 渗透三件套：`session_http`（cookie jar + request_id）/ `replay_request`（原样重放 + 状态码与正文哈希比对）/ `report_gen`（markdown + SARIF 2.1.0） | `2295de0` | 本地靶场：登录后私有页 401→200；重放判定一致/动态内容；SARIF 容器结构校验 |
| P1-4 | 两套人格写入**阶段化流水线**（渗透：资产发现→漏洞识别→验证→报告；CTF：信息→假设试错→求解→收口） | 同上 | 人格文件（软约束，机制仍在闸门） |
| P1-5 | 技能导出按会话键分目录（`data/dsh-skills/<key>`），与 `customSkillDirs` 同源 | 同上 | 命令插件用例（sessionKey=ctf-web → 独立目录） |
| P1-2 | CTF 补 `checksec_bin`（`pwn checksec`，docker 档 fail-closed） | `3bf8aa1` | 容器真跑用例（Docker 恢复后生效，判据 `RELRO`） |
| P1-3 | 同名工具覆盖不再静默（去重器留 note；RayScan 适配器 vs MCP 声明即此例） | 同上 | `test_registry` 重名留痕用例 |
| — | **测试当场抓出并修掉一个凭据泄漏**：登录响应的 `Set-Cookie` 值原样回吐 → 新增 `mask_response_headers`（`http_raw` 与 `session_http` 都走） | `2295de0` | `test_http_session` 断言输出里不含 cookie 值 |

### 阶段 2 · 监督与度量（部分完成）

| # | 交付 | 提交 | 状态 |
|---|---|---|---|
| P2-1 | 宿主侧监督插件 `proteus-supervisor.mjs`：同工具+同参数重复到阈值即 deny（理由可操作），第二次升级为 `ask`，留痕进 spool | `3bf8aa1` | 完成（5 条用例） |
| P2-4 | 注入护栏写进两套人格：工具返回的目标内容一律不可信；只有人的消息才算指令 | 同上 | 完成（软约束，机制侧仍是白名单+审批） |
| P2-2 | CTF 评测分档（unguided / subtask / subtask-guided） | `—` | **完成（2026-09-24）**：里程碑由题集真值派生（不手写 33 份）、判据落在**工具输出**上；`benchmark --suite ctf` 出分档行。实测参考解 33/33 且里程碑均值 100% |
| P2-3 | 审计层级视图（Task / Action / Artifact） | — | **待做**：现有 `evidence_report` 已给任务清单与步骤；层级视图要先把 链上记录 ↔ 任务 的关联补上 |

阶段 1+2（已完成部分）验收：全量 **499 passed / 16 skipped**；三个 preset
`--check` 全绿、roster 均未 broken。

**最该补的一次冒烟**：起 web profile，选 `proteus-ctf-web`，验证
① 工具面只有 CTF 那 15 个；② `/proteus-scope add <靶机>` 后 `http_raw` 立即可用；
③ 连点同一个调用 3 次被监督层拦下。

---

## 七、真机冒烟记录（2026-09-24 晚）

**起法**：`dsh\start-proteus.cmd`（web profile + host 补丁），DSH 起来了并打印
token URL；`dsh_install --check` 在启动前已全绿。**UI 侧未能完成点击级验证**
（原因见 7.2），改用**已安装 preset 的真实配置**做会话级验证——三者判定层相同。

### 7.1 三个检查点（原始输出摘录）

**① 工具面（按已装 preset 的 `mcp-proteus` 行 args 挂载内核）**

```
proteus-pentest     52 工具 | CTF 件 无 | nuclei=有 | 外部家族 ['chameleon','rayscan','seckb']
proteus-ctf-web     34 工具 | CTF 件 ['checksec_bin','codec_chain','codec_decode',
                                     'file_type','python_solve','rsactf_attack']
                                | nuclei=无 | 外部家族 ['chameleon','seckb']
proteus-ctf-crypto  19 工具 | CTF 件（同上 6 件）| nuclei=无 | 外部家族 ['seckb']
```

`ctf-web` 全清单（34）：chameleon 12 + seckb 4 + CTF 六件套 + 侦察/HTTP 八件
（`http_raw`/`http_probe`/`dns_lookup`/`robots_fetch`/`port_scan`/`session_http`/
`replay_request`/`report_gen`）+ 元能力 4（`pentest_set_mode` 等）——**无 nuclei/sqlmap**。
计数自洽：18 + 12 + 4 = 34；`ctf-crypto` 15 + 4 = 19；渗透 33 + 16 + 3(rayscan) = 52。
**RayScan 这次在跑**，所以渗透面多了它的 3 个工具；CTF 面不含 `rayscan_*`（未列入 allow）。

**② 会话授权（内核先拒 → 真实命令插件授权 → 同一连接随即放行）**

```
授权前  http_raw http://127.0.0.2/ → isError=True
        "目标 'http://127.0.0.2/' 不在授权范围 ['127.0.0.1','localhost']。
         若确需访问，由人在会话里执行 /proteus-scope add http://127.0.0.2/（或 CLI…）"
命令    before: 会话授权目标: (空——只有 --targets 基线)
        add   : 会话授权已更新: 127.0.0.2
授权后  同一连接再调 → isError=False（连接被拒是靶机没开，不是策略拒绝）
```

**③ 监督层（按真实 preset 行的阈值 5）**

```
连调 6 次同参数 → ['next','next','next','next','deny','ask']
留痕: kind=supervisor decision=deny repeats=5 session=smoke
```

**顺带验证了 P0-6 的会话键隔离**：`data/session-mode.json` 里留着
`pentest-standard`（历史残留），而三个 preset 各自回落到自己的
`--default-mode`——CTF 面没有被那条残留文件带偏（读的是
`session-mode-<key>.json`）。

### 7.2 UI 侧未完成的原因（环境问题，非 preset 问题）

| 观察 | 证据 |
|---|---|
| DSH 服务端正常 | `python`（identity/gzip、chunked）与 PowerShell 都完整取到文档：**200 / 39893 字节**，四种 `Accept-Encoding` 全通过 |
| 桌面浏览器加载文档失败 | `browser.tabs.open`/`navigate` → `ERR_INCOMPLETE_CHUNKED_ENCODING (-355)`；控制台同错，且**插件包 URL**（`/plugins/??…client.js`）同样 -355 |
| 小响应可以 | `/favicon.ico` 正常加载；同一 tab 内 `fetch('/')` **偶发成功**（拿到完整 39893 字节）——典型的传输层不稳定 |

结论：**Electron 浏览器 ↔ DSH 的本地 HTTP 传输对"大响应 + chunked+gzip"不稳**，
与本仓库的 preset / 插件 / 内核无关（HTML 是静态壳，与加载了哪些行无关）。

**绕过办法（给人用）**：启动器打印的 token URL 直接用**系统浏览器**（Edge/Chrome）
打开即可——那是 DSH 原本的用法（启动器会尝试自动打开）。想在桌面浏览器里跑，
需要先解决那条传输问题（重启桌面浏览器进程／换端口重试）。

另注：启动日志有一条 **DSH 自身的**告警——
`ui-settings-updates (@deepseek-ai/dsh-client-ui-settings-updates): failed to import`
（客户端 UI 插件的服务端半体导入失败），与本仓库改动无关，但值得在 DSH 升级时一并复核。

---

## 七、风险与开放问题

1. **三 preset = 三个内核进程**（roster 在进程启动时挂载）：启动耗时与内存 ×3。P0-1 完成后每进程
   应在秒级；实装后需实测常驻内存与启动总时长。
2. **命令插件不能直接弹审批卡**：DSH 的审批栈作用在工具调用上。D4 的落地形态是
   "**永久授权 = 人工命令**（`/proteus-scope`），**一次性放行 = 审批卡**（越界目标触发 ask）"——
   需真机确认 ask 路径确实能覆盖内核工具调用（内核 `ask` 档已被 `--authorize` 抬起，实际把关在 DSH 侧）。
3. **`tools/list_changed` 需真机验证**：源码已确认 DSH 注册了 `listChanged.tools.onChanged`，
   但"内核发通知 → DSH 刷新 → 模型看到新工具面"这条链路未跑过。
4. **进程级状态与并发**：`session-mode.json` / `session-scope.json` 是进程级单文件，同 preset
   多会话并行会串。需要真机确认；必要时改为按 session id 分文件。
5. **注入面**：`http_raw` 等工具会把目标页正文喂进模型上下文（CAI 已论证这类攻击面）。
   护栏是 P2-4，但"目标内容不可信"这条应同时写进 persona（软约束先行）。
6. **Jeopardy CTF 已饱和**（CAI/CSI 结论）：CTF 模式的定位是**练手与真实比赛**，
   不追刷分；能力投入优先给渗透与 A&D 方向。
7. **本地项目依赖**：poxiao / ruoyi / RayScan 等仍在工具面里（绑本机路径、宿主直跑）。
   本次改造**不动它们**，但按"锦上添花"标准，后续应逐个降级为可选增强或替换为开源等价物。

---

## 八、与既有文档的关系

| 文档 | 关系 |
|---|---|
| `docs/DSH插件化与内核旁路治理.md` | 本文的**前身**（三步走已全部实施）；本文是"第四步：以 DSH 为主体"的形态定稿 |
| `docs/DSH宿主接入指南.md` | 接入与排查手册；三 preset 实装后需同步更新第二/四/六节 |
| `docs/能力加强路线.md` | 六方向中 A（宿主分工）/ B（工具层）/ D（评测）/ E（上下文）的**决策落地版**；E 方向由 DSH 侧承担 |
| `docs/修复待办清单.md` | 本轮新增项（启动健壮性、CTF allow、工具面可见性、多 preset 同步）应登记为 R-25 起的条目 |
| `AGENTS.md` | 实装后需更新第 1 节"宿主层现状"与第 3 节"关键事实"（preset 数量、工具面口径） |
