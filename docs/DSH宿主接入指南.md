# DSH 宿主接入指南（方案 D）

> 把 Proteus 内核挂载为 deepseek-harness 的 agent-preset：**只配置，不改 DSH 核心代码**。
> 适用 DSH 版本：`0.1.6-alpha.2`（preset 基座版本；本机 `$DSH_HOME` = `<USER_HOME>\.dsh`）
> 接入日期：2026-09-17（2026-09-22 增补裁决层与审计层，见第八节第 8/9 条）

---

## 一、分层：什么写在 preset 里，什么不能

DSH 的 composition 分两个平面，这决定了本接入的每一行写在哪里：

| 平面 | 拥有什么 | 本接入的落点 |
|---|---|---|
| **AGENT 平面**（agent-preset） | 一个会话往注册表里放什么：人格、工具 | `agent.cordis.yml`：persona 行 + MCP 工具行 |
| **HOST 平面**（bundle / profile） | 注册表本身、沙箱与审批栈、模型路由、持久化 | 审批档位 → `proteus.cordis.patch.yml`（按 id 覆盖 host 行） |

**审批档位为什么不写在 preset 里**：`@deepseek-ai/dsh-user-approval` 与
`@deepseek-ai/dsh-permission-presets` 由 `packages/bundle/base/cordis.patch.yml`
挂在 host 平面；随包发布的三个 preset（standard / minimal / ptc / cordis）也都不拥有它。
preset 里再挂一次，要么与根 realm 冲突（`provide()` 二次注册同名服务会抛错），
要么落在私有 realm 里造一份 host 读不到的副本。DSH 提供的正确姿势是按 id 覆盖 host 行。

---

## 二、交付物与安装位置

仓库内（版本受控）：

```
proteus-agent/
├── dsh/
│   ├── .agent-presets/proteus/          # preset（AGENT 平面）
│   │   ├── agent.cordis.yml             # preset 本体：3 行 Proteus 专属内容
│   │   ├── proteus-persona.mjs          # 本地插件：读人格文件并注册分区
│   │   ├── proteus-tools-policy.mjs     # 本地插件：目标动作裁决 + 内核缺位守卫
│   │   └── preset.yml                   # 显示名/描述/排序
│   ├── proteus-bridge/                  # host 平面 bundle：会话事件审计入 spool
│   └── proteus.cordis.patch.yml         # host 平面补丁：审批档位绑定
├── prompts/dsh-persona.md               # 宿主侧人格提示词（persona 的唯一来源）
└── tools/dsh_install.py                 # 同步 + 漂移校验 + roster 健康检查
```

**同步（推荐）**——幂等；`--check` 只校验不改动：

```bash
python tools/dsh_install.py          # 同步 preset 到 $DSH_HOME，并校验
python tools/dsh_install.py --check  # 只检查：与仓库是否同步 / 补丁 / 审计桥接线
```

它挡四类**静默失效**：① **跑旧代码**——逐文件比对哈希，安装副本落后于仓库即报
（启动器 [start-proteus.cmd](start-proteus.cmd) 会在每次启动前同步）；② **漏拷文件**
——逐行核对相对 specifier（少一个 `.mjs` 会让整份 preset **broken 并在选择器里
静默消失**）；③ `!!js` 行里的 `": "`（YAML 会把它拆成映射键、求值成
`[object Object]`）；④ roster 健康检查。

> **preset 目录不能用链接代替复制**（2026-09-22 实测）：DSH 的 preset 发现机制
> **不跟随 reparse point**。把 `$DSH_HOME/.agent-presets/proteus` 建成 junction 后，
> `discoverPresets` 的返回从 2 个 preset 变成 1 个——proteus **直接从选择器里
> 消失且无任何提示**。所以只能是真实目录 + "启动前同步"。备份也必须放在 preset
> 根**之外**（`$DSH_HOME/backups/`），否则会被发现机制当成一个 preset。

**手工同步（等价，仅在不能跑脚本时）**——注意是**四个**文件，漏一个即 broken：

```bash
mkdir -p ~/.dsh/.agent-presets/proteus
cp dsh/.agent-presets/proteus/{agent.cordis.yml,proteus-persona.mjs,proteus-tools-policy.mjs,preset.yml} \
   ~/.dsh/.agent-presets/proteus/
```

**审计层（host 平面 bundle）走官方安装路径**，装完**重启 DSH 进程**：

```bash
dsh plugin --profile web add <REPO>/dsh/proteus-bridge
```

> **本机实测的两个前提**（2026-09-22，解释了 09-21 为什么"官方路径失败、只能手工登记"）：
>
> 1. **pnpm 11 不再从项目 `.npmrc` 读 `store-dir`**——它必须写在
>    `pnpm-workspace.yaml` 的 `storeDir`（pnpm 10+ 的设置新家）。缺了它，
>    `pnpm add` 会以 `ERR_PNPM_UNEXPECTED_STORE` 失败：profile 的
>    `node_modules` 链自 `~/.pnpm-store\v11`，而 pnpm 想用默认的
>    `%LOCALAPPDATA%\pnpm\store\v11`。
> 2. **装完 `node_modules/dsh-proteus-bridge` 必须是链接**（junction，可用
>    `fsutil reparsepoint query` 验）。若是普通目录，说明它是**旧副本**：实测踩中过
>    ——09-21 的手工兜底留下普通目录副本，而仓库里的桥 09-22 已重构成薄再导出，
>    审计层因此跑了两天前的代码且毫无提示。`--check` 会报这一条。

发现机制（`packages/preset/agent-presets/src/discovery.ts`）：
根目录 = `$DSH_HOME/.agent-presets`（用户可写，随包发布的 preset 另有一个只读 system 根）；
**目录名即 preset id**（须匹配 `/^[a-z0-9][a-z0-9-]*$/`，故用 `proteus`）；
`agent.cordis.yml` 顶层是**插件行列表**；行内 `name` 既可写包名，也可写相对本目录的
文件路径（`./proteus-persona.mjs` 即按 preset 目录解析）。
发现是每次调用重新扫盘的，**新写的 preset 不需要重启进程就能被看到**。

> 注意：`agent-presets` 由 **web-app bundle** 挂载（`config: {default: standard}`，
> 用户根自动纳入）；**headless bundle 不挂它**，所以 `dsh --profile headless` 里没有
> preset 可选——会话侧验证请用 web profile。

---

## 三、审批档位绑定（host 平面补丁）

```bash
# 单次启动叠加
dsh --profile web --patch <仓库>/dsh/proteus.cordis.patch.yml

# 或固化到本机：把补丁里的行并入 $DSH_HOME/cordis.patch.yml（机器本地层，
# 优先级高于 profile 层，低于命令行 --patch）
```

补丁定义了三个 Proteus 档位（官方三档原样保留）：

| 档位 | sandbox | approval | 适用 |
|---|---|---|---|
| `proteus-safe` | read-only | ask | 侦察与证据固化 |
| `proteus-standard` | workspace-write | ask | 常规渗透（默认） |
| `proteus-ctf` | danger-full-access | never | CTF 解题（工具密集，不逐步打断） |

补丁是**整行 config 替换**而非深合并，所以官方三档在补丁里重申了一遍；
`defaultPreset` 默认注释掉（保持部署原有默认，需要时取消注释即把
`proteus-standard` 设为新会话默认档）。

---

## 四、启动与选择 preset

**一键启动（推荐）**：仓库提供了启动器，双击或命令行运行即可（前置：用户环境变量 `PENTEST_WS` / `PENTEST_PY312` 已 setx——本机 2026-09-18 已配置）：

```bash
<REPO>\dsh\start-proteus.cmd
```

启动器做四件事：校验环境变量 → **同步并校验 preset** → **若已有实例在跑就先关掉它**
→ 带 host 补丁启动 web profile。启动后终端打印带 token 的地址，在会话的 preset 选择器里选
**「Proteus 千面」（order: 5）**，新会话即挂载本 preset。

> **为什么必须先关旧实例**（2026-09-22 实测两次踩中）：4080 被占时新实例会
> `dsh: startup failed: webserver (required) listen EADDRINUSE 127.0.0.1:4080`
> **启动失败并退出**——而双击的人只看到窗口一闪，以为重启成功了。
> 启动器因此**默认直接关掉旧实例再启动**（不问：双击启动器本身就是明确的启动意图，
> 多问一句只是多一个失败点；要问用 `--ask`）。关掉旧实例 = 当前 GUI 会话结束，
> 但**对话是持久化的，不会丢**。只想看检查结果、不想关任何进程：`python tools/dsh_install.py --check`。

**手动启动（等价）**：

```bash
cd <WS>/deepseek-harness
node apps/cli/lib/bin.js --profile web --patch <REPO>/dsh/proteus.cordis.patch.yml
```

> 环境变量说明：preset 的 `promptPath` / `command` / `cwd` 通过 `!!js` 读取 `PENTEST_WS` 与 `PENTEST_PY312`（`PENTEST_PY312` 指向解释器目录，自动拼 `/python.exe`）。改动 setx 后需**重启 DSH 进程**才生效。

也可以把 `dsh/proteus.cordis.patch.yml` 的行并入 `$DSH_HOME/cordis.patch.yml` 固化为默认，之后任何 `dsh` 启动都带 Proteus（不再需要 --patch）。

---

## 五、验证步骤

### 5.1 发现与健康（不需要起会话）

用 DSH 自己的发现机制读一次 roster——选择器读的就是它；`broken` 为空即说明
composition 可解析、且每一行都能解析到模块：

```bash
cd ~/.dsh/profiles   # 该目录的 node_modules 里装着 harness 包
node --input-type=module -e "
import { discoverPresets } from '@deepseek-ai/dsh-agent-presets'
import { homedir } from 'node:os'; import { join } from 'node:path'; import { pathToFileURL } from 'node:url'
const roots = [{ path: join(homedir(), '.dsh', '.agent-presets'), trust: 'user' }]
const found = await discoverPresets(roots, pathToFileURL(join(process.cwd(), 'x')).href)
for (const p of found) console.log(p.id, 'broken=' + (p.broken ?? '否'))
"
```

**这个检查覆盖到哪、没覆盖到哪**（2026-09-17 实测核对源码所得）：

- 覆盖：composition 文件用 Loader 自身的 YAML 方言解析通过；每一行的 **specifier
  可解析**（包是否装在本机 harness、相对路径的文件是否存在）。
- **不覆盖**：行 `config` 里的路径与表达式。`broken` 的判据是 `rowResolves()`，
  它只看行的 `name`，**不看** `command` / `cwd` / `env`。python 路径写错、`cwd`
  指错目录，`broken` 依然是空。
- **不覆盖**：`!!js` 表达式的求值。DSH 源码里写明了这个取舍——health 检查刻意
  不评估 `!!js`（`lib/index.js`：*the one carrying `!!js` ... so health can never
  call a composition broken*），求值发生在真正挂载时（Loader 的 `internal/config`
  钩子 → `interpolate()` 递归求值整份行 config，包括嵌套的 `env`）。

所以 `broken` 为空只说明「这份 preset 能装上」，不说明「装上了内核一定起得来」。
后者要靠 5.2 / 5.3 或真机会话（5.4）验证。

**改了 preset 目录里的 `.mjs` 插件后，必须完全退出 DSH 进程再启动。**
composition 的 YAML 每次切换 preset 都会重新解析（改 `.yml` 立即生效），但
loader 对插件模块的 `import` 走 Node ESM 缓存——**进程不重启，旧模块一直
在**（实测：修掉 `.yml` 的 schema 错误后 mcp 行报错消失，而 `.mjs` 里的
旧代码仍报 order 校验失败，同一进程内重试两次皆如此）。判断技巧：错误
信息若与已修复内容不符，先重启 DSH 再说。

另一个 `!!js` 的坑：表达式**整行禁止出现 `": "`（冒号+空格）**——会被
YAML 当成映射键拆掉，得到 `[object Object]`。三元写法请改 `||` 短路形式
（例见 `agent.cordis.yml` 的 `command` 行）。

### 5.2 MCP 行能否拉起内核（不需要起会话）

preset 里那一行的命令，单独跑一次即可确认工具清单：

```bash
cd <REPO>
python -c "
import sys; sys.path.insert(0,'.')
from penagent.mcp_client import MCPServerSpec, probe_server
spec = MCPServerSpec(name='proteus', transport='stdio',
                     command=(r'<PY312>\python.exe','-m','penagent','mcp','--data','data','--targets','127.0.0.1'),
                     workdir=r'<REPO>', timeout=60.0)
tools, reason = probe_server(spec); print(len(tools), 'tools |', reason or 'OK')
"
```

### 5.3 用 DSH 自己的 mcp-client 挂载（最接近会话的验证）

不启动 UI，直接在本机 harness 环境里用**与 preset 完全相同的配置**挂载 DSH 自带的
`@deepseek-ai/dsh-mcp-client`，断言注册出的工具名并真实调用：

> **先交叉核对（必做）**：下面的 config 是 preset 里那一行的**人工副本**，不是从
> preset YAML 派生的。preset 里的 `command` / `cwd` 写错时，5.1 的 `broken` 不会
> 报（它不看行 config），而本步骤会因为抄的是正确值而通过——形成假阴性。
> 所以跑之前先对一遍：
>
> ```bash
> grep -nE "^ *(- id:|command:|cwd:|args:|transport:|toolCallTimeoutMs|failOnStartupError)" \
>   <仓库>/dsh/.agent-presets/proteus/agent.cordis.yml
> ```
>
> 与下方脚本里的 `command` / `cwd` / `args` 逐字一致再往下走；不一致以 preset 为准，
> 并回头修脚本或 preset（两者的差异本身就是问题）。

```bash
cd ~/.dsh/profiles          # 该目录的 node_modules 里装着 harness 包
cat > verify-proteus.mjs <<'JS'
import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import { apply } from '@deepseek-ai/dsh-mcp-client'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
const config = {
  transport: 'stdio', serverName: 'proteus',
  command: '<PY312>/python.exe',
  args: ['-m', 'penagent', 'mcp', '--data', 'data', '--targets', '127.0.0.1'],
  cwd: '<REPO>',
  env: {}, toolCallTimeoutMs: 600000, failOnStartupError: false,
}
const ctx = new Context()
await ctx.plugin(SystemPrompt); await ctx.plugin(ToolRuntime)
await apply(ctx, config)
const names = ctx.tools.schemas().map(s => s.name).filter(n => n.startsWith('mcp__proteus__'))
console.log('注册工具数:', names.length)
const r = await ctx.tools.execute({ signal: new AbortController().signal,
  callId: ToolCallId('v1'), name: 'mcp__proteus__port_scan',
  arguments: { host: '127.0.0.1', ports: '80' } })
console.log('调用 port_scan -> isError =', r.isError, JSON.stringify(r.content).slice(0, 120))
await ctx.fiber.dispose()
JS
node verify-proteus.mjs && rm verify-proteus.mjs
```

本机实测：**注册 24 个 `mcp__proteus__*` 工具**；`pentest_missions` / `pentest_skills`
返回 `[]`、`port_scan` 返回真实扫描结果（`isError=false`）——即"可见且可调用"。

> **协议要求**：DSH 的 mcp-client 用官方 SDK，会严格校验报文。工具的 `tools/list`
> 必须给规范的 `inputSchema`（`{type: "object", properties: {...}}`），`tools/call`
> 必须把结果包成 `content` 内容块数组——缺任一项，SDK 解析失败后**一个工具都注册不上**，
> 而 `failOnStartupError: false` 会让这种失败保持安静。内核侧的 MCP server 已按此修正。

### 5.4 会话内可见与可调用（UI 验收）

在 web 会话里选「Proteus 千面」后：

1. 让模型列出工具，应看到 `mcp__proteus__*` 一组（工具在会话内的公开名由
   mcp-client 统一加前缀：`mcp__<serverName>__<rawName>`，serverName 取 `proteus`）。
2. 调一个只读工具，例如让它执行 `mcp__proteus__pentest_missions`（列作战记录）
   或 `mcp__proteus__port_scan`（目标限 127.0.0.1）——返回 JSON 即链路通。
3. 触发一次审批：调 `mcp__proteus__nuclei_scan` 这类高危工具，应按当前档位弹审批。

---

## 六、工具清单与命名

实测（本机 2026-09-22，用 5.2 的命令并加 `--discover-mcp`）：**45 个工具**，
公开名一律 `mcp__proteus__<原名>`。

| 类别 | 数量 | 工具 |
|---|---|---|
| 高层能力（内核驱动） | 4 | `pentest_run` / `pentest_skills` / `pentest_missions` / `pentest_reflect` |
| 内置被动侦察 | 5 | `port_scan` / `http_probe` / `http_raw` / `dns_lookup` / `robots_fetch` |
| 外部 CLI（本机已安装的才注册） | 16 | `httpx_probe` / `nuclei_scan` / `sqlmap_auto` / `ffuf_fuzz` / `gobuster_dir` / `fscan_scan` / `naabu_scan` / `dalfox_xss` / `subfinder_enum` / `dnsx_lookup` / `katana_crawl` / `ehole_finger` / `pocsuite_poc` / `poxiao_scan` / `poxiao_recon` / `ruoyi_scan` |
| 适配器（PacketForge） | 3 | `pf_nmap_scan` / `pf_nmap_services` / `pf_nmap_vuln` |
| 外部 MCP（需 `--discover-mcp`） | 17 | chameleon 12（`chameleon_scrape_url` / `chameleon_crawl_site` 等）+ seckb 4（`seckb_kb_search` 等）+ rayscan 1（`rayscan_scan`） |

工具清单来自内核的统一注册中心（`penagent/registry.py`）：新增工具改配置即可，
内核与宿主两侧都不用改代码。

---

## 七、排查

| 现象 | 原因与处置 |
|---|---|
| 选择器里没有 proteus | 目录名不合法（须 `[a-z0-9][a-z0-9-]*`）或没放进 `$DSH_HOME/.agent-presets/`；跑 5.1 看 roster |
| roster 显示 broken | composition 的 YAML 或行解析失败，`broken` 字段会写明是哪一行、哪个 specifier |
| 会话里没有 `mcp__proteus__*` | 内核没起来。`failOnStartupError: false` 会让 preset 照常挂载，只是少这组工具——按 5.2 单独验证命令；常见原因是 `command` 里的 python 路径失效或 `cwd` 不对 |
| preset 在选择器里消失 | 整份 composition broken（某行解析不到），**或目录是链接**（发现机制不跟随 reparse point）。`python tools/dsh_install.py --check` 会指出原因 |
| 双击启动器后"好像没重启" | 旧实例还占着 4080，新实例以 `EADDRINUSE: address already in use 127.0.0.1:4080` **启动失败并退出**（窗口一闪，看不到报错）。启动器现在**默认直接关掉旧实例再启动**；若它仍失败，手动兜底：任务管理器结束 `node.exe`（命令行含 `--profile web`）后双击启动器 |
| 改了仓库，会话行为没变 | 两种原因，`--check` 分别报得出来：① 安装副本过期 →"与仓库不同步"，跑不带 `--check` 即同步（启动器每次启动前也会同步）；② **副本是新的、但进程还在跑旧模块**（Node 的 ESM 缓存不重启不更新，见 5.1）→ 两条判据：进程那条报"DSH 进程 pid=… 启动于 …，早于安装文件的最新改动"；**spool 那条**报"审计桥仍在跑旧代码：最新记录没有 `preset` 字段"。后者与"怎么启动的"无关，最可靠。两种都只能重启 |
| 审计层像是旧版本 | `node_modules/dsh-proteus-bridge` 是普通目录而非链接（旧副本）。`--check` 会报；按 §二 用 `dsh plugin add` 重装 |
| `dsh plugin add` 报 `ERR_PNPM_UNEXPECTED_STORE` | pnpm 11 不再读项目 `.npmrc` 的 `store-dir`；在 profile 的 `pnpm-workspace.yaml` 里加 `storeDir` 指向 `node_modules` 实际链自的那个 store（见 §二 的实测前提） |
| `pentest_run` 报 LLM 相关错误 | 该工具会在内核里跑 LLM 决策循环，需要 `PENTEST_LLM_*`；preset 已从宿主环境透传这三个变量，缺失时内核走默认端点 |
| 工具调用被审批挡住 | 当前会话的权限档位；用第三节的补丁切换 `proteus-ctf`（approval: never）或逐次批准 |

---

## 八、边界与已知限制

1. **只配置，不改 DSH 核心代码**：本接入只新增 `$DSH_HOME/.agent-presets/proteus/`
   与一个 host 补丁；DSH 仓库一行未改。
2. **人格文件的选择**：persona 取自 `prompts/dsh-persona.md`（宿主侧版本）。
   内核的 `prompts/pentest.md` 带 `{tools}`/`{skills}` 占位符与"输出严格 JSON"的
   决策协议——那是给内核 ReAct 循环用的，直接挂进 DSH 会话会带着未替换的占位符、
   并要求模型输出 JSON 而不是调用工具。两者同源，取向不同；
   要用原始文件可改 preset 里的 `promptPath`。
3. **模式与 DSH 审批是两套闸（各司其职，都已生效）**：DSH 侧审批（host 平面）
   管"这次调用要不要批准"，内核侧 ModeProfile 管"这个工具在该模式下是否可见/
   可执行、参数冻结、预算与判定器"。`mcp__proteus__<底层工具>` 与
   `mcp__proteus__pentest_run` **两条路径都经过内核闸门**。

   > **历史修正（2026-09-21）**：本条此前写"内核的 MCP 底层工具入口**目前直连
   > 注册表、未过 Policy**……`--targets` 目标白名单同样不生效……那份 policy 是死
   > 代码"，描述的是 commit `02557bd` 修复**之前**的状态。现已修复：
   >
   > - 闸门（目标白名单 + 高危授权 + 协议白名单）由 `ToolRegistry` 持有，裁决在
   >   `execute()` 内部、工具体之前——ReAct 循环 / MCP 底层工具 / Web 子进程都
   >   绕不过去；
   > - `PentestMCPServer` 把 `--targets` 接进闸门，并新增操作员级 `--authorize`
   >   （**调用参数里的 `authorize` 一律不生效**，避免模型自我授权）。
   >
   > 复测见 `docs/DSH宿主实测记录.md` 第九节：`port_scan` 打 `127.0.0.2` 返回
   > `isError=true` + `duration_ms: 0`（拒绝发生在工具体之前）；同节还记录了复测
   > 过程中揪出的白名单解析缺陷及修复（`Policy.normalize_targets`）。

   档位选择因此不必再按"内核不设防"来定——内核侧始终有闸；`proteus-ctf` 的
   `danger-full-access` 放宽的是**沙箱**，不是内核白名单。
4. **失败语义已正确映射到 `isError`**：内核 MCP server 的 `_result()` 现按
   `ToolResult.ok` / `outcome` 映射 `isError`，工具异常也走 `isError=true` 的结构化
   结果（不占用协议级 `error`）。客户端可直接用 `isError` 判断成败。

   > **历史修正（2026-09-21）**：本条此前写"失败一律报成成功：`isError` **恒为
   > `false`**"，并附两种逃逸形态的实测表——那描述的是 `02557bd` 修复前的状态，
   > 现已修复。回归用例见 `tests/test_mcp.py::test_pentest_run_unknown_mode_is_structured_error`
   > （断言 `isError=True`）。
5. **安全前提（全路径一致）**：默认目标白名单仅 127.0.0.1/localhost。
   该前提对 `pentest_run` 与 `mcp__proteus__<底层工具>` **两条路径都成立**——
   闸门由 `ToolRegistry` 持有、裁决在 `execute()` 内部，两者都绕不过去。

   > **历史修正（2026-09-21）**：本条此前写"该前提**只在 `pentest_run` 路径成立**，
   > `mcp__proteus__<底层工具>` 路径不成立"——那描述的是修复前的状态，现已全路径
   > 生效。复测见 `docs/DSH宿主实测记录.md` 第九节。

   另注意 DSH 路径下有两套**独立的松紧旋钮**：内核 `ask` 档（被 preset 的
   `--authorize` 放开，不再拦内层工具）与 **DSH 的 `approval` 档位**（实际把关者，
   见 `dsh/proteus.cordis.patch.yml`）。用哪道闸、开多松，由 preset 档位决定。

6. **函数型工具静默丢弃未知参数**：`ToolRegistry.execute` 先按 `spec.parameters`
   过滤实参再调用（`penagent/tools.py:100`），所以传错参数名不会得到"未知参数"提示，
   而是参数被丢掉、再由 Python 抛缺参 TypeError（实测 `robots_fetch` 传 `url` 得
   `missing 1 required positional argument: 'base_url'`）。客户端只要照着
   `inputSchema` 传参就不受影响，但报错信息对模型不友好。属内核范围，本次仅记录。

7. **MCP 行现在带两个关键参数（2026-09-21 起）**：`--default-mode pentest-standard`
   与 `--discover-mcp`。

   - `--default-mode`：`pentest_run` 的 `mode` 是**可选**参数，模型省略时此前会走
     无模式路径——沙箱裁决缺失（危险 CLI 工具直跑宿主）、记忆落 `default` 分区、
     步数退回 12。现在省略即回落到 `pentest-standard`，模式约束始终在线
     （见 `docs/修复待办清单.md` R-1）。
   - `--discover-mcp`：真正连接 `mcp_servers.json` 声明的外部 server。默认不连接是
     为避免启动被不可达的外部服务拖住，代价是这些能力悬空（R-14）。实测开启后
     外部 MCP 工具全部到位（chameleon 12 + seckb 4 + rayscan 1），工具总数 **45**
     （分类见第六节）；不可达的 server 会**优雅跳过**并记入 `summary().notes`，不抛异常。

8. **内核缺位守卫（2026-09-22 新增，fail-closed）**：`failOnStartupError: false`
   意味着内核起不来时会话照常、只是**没有 `mcp__proteus__*`**，界面上没有任何提示。
   那种会话里"对目标发请求"既无模式闸门也无证据链，放行等于"为能用而放弃保护"。
   裁决行因此在动手前先看**调用方 agent 作用域里有没有内核工具**
   （`ctx.tools.schemas(exec.agent)`）：

   | 判定 | 行为 |
   |---|---|
   | `yes`（工具面里有内核工具） | 按 `mode` 正常裁决（缺省 `ask`） |
   | `no` + `kernelGuard: deny`（缺省） | 目标动作**直接拒绝**，理由带排查命令 |
   | `no` + `kernelGuard: warn` | 按原档位走，但理由注明"本次动作没有内核校验" |
   | `unknown`（拿不到工具服务） | **按原档位走**——DSH 是 pre-stable，把"API 变了"误判成"内核没了"会把健康会话整片拒掉 |

   判定结果一并写进 spool（`kernel: yes/no/unknown`），证据链里因此能区分
   "被闸门拦下"与"内核根本没起来"。本地操作（读写文件、跑本地脚本）不受影响。

9. **三层分工是实测结论，不是设计偏好**：`tools/pre-execute` 与 `tools.restrict`
   都按**作用域**派发，而 `session/event` 是**全局**事件。于是：

   | 层 | 放什么 | 为什么 |
   |---|---|---|
   | host 平面 bundle | 只做全局事件审计 | 作用域内的裁决监听在这里**收不到**调用 |
   | preset 内本地插件行 | 裁决 + 工具面收敛（restrict） | 作用域过滤的机制只在这里生效 |
   | MCP server | 工具能力本体 | 与 DSH 版本解耦，升级不 breaking |

   > 这条违反直觉（直觉会想把所有东西塞进 host 平面）。2026-09-22 真机实测推翻过一次：
   > 挂在 host 平面的裁决行在 web 会话里**完全收不到**工具调用，而同一份代码挂在
   > 无 preset 的 headless profile 里能拦住。

10. **preset 目录不能用链接**（2026-09-22 实测）：发现机制**不跟随 reparse point**，
    把 preset 目录建成 junction 后它就从选择器里静默消失了（`discoverPresets`
    返回数 2 → 1）。所以 preset 是"真实目录 + 启动前同步 + 漂移校验"，备份也要放在
    preset 根之外。**bundle 层不受此限**——它由 Node 的模块解析从 `node_modules`
    加载，官方 `link:` 依赖 + junction 正是正确形态。与第 9 条同源：DSH 的行为
    只能靠真机验证，静态读文档会得到"链接更干净"这种看起来对、实际会坏的结论。

11. **审计链的 preset 归属**（2026-09-22 加，对应待办 R-22）：`session/event` 是
    **全局**事件，同一个 DSH 进程里**所有会话**的调用都会进 spool。所以每条审计
    记录都带 `preset`（取 `SessionHeader.agentPreset`），`--suite dsh-session`
    默认只算 `preset=proteus` 的记录（`--preset ''` 关掉过滤）。

    | 情形 | 行为 |
    |---|---|
    | 有归属且等于目标 preset | 计入 |
    | 有归属但不是目标 preset | **不计入**（别的会话碰过同一个靶，不再给它加分） |
    | **归属未知**（`''`，老链或形状变化） | **计入**——静默丢审计比多留危险得多 |

    插件侧也可直接过滤：`presets: ['proteus']`（缺省空 = 全记但打标；归属未知的
    会话仍会记录）。`tools/pre-execute` 载荷里没有 session，所以**裁决记录**的
    `preset` 是尽力而为（取不到就是 `''`）；权威归属来自 `session/event` 那条路。

12. **DSH 路径上到底靠哪一道闸**（2026-09-23 收口待办 R-13）：MCP 是**非交互**通道，
    内核的 `ask` 档**没有可以被问的人**——`penagent/agent.py` 的 `Policy.check` 对
    `ask` 与 `dangerous` 一律 `return False`（**是拒绝，不是弹窗**）。所以 preset 的
    MCP 行必须在服务端启动时就带 `--authorize`：不带的话 sqlmap / nuclei / ffuf 这类
    工具**全部不可用**，模型只能转回宿主 shell——正是 R-1 与 R-11 那个"为了能用而
    放弃保护"的恶性循环。

    代价与边界：`--authorize` 抬起的是**内核的 ask 档与 dangerous 标记**，它
    **抬不动**下面这些（都不看 `authorize`）：

    | 仍在内核侧生效 | 说明 |
    |---|---|
    | `capability.deny` / `permission.hard_deny` | 模式禁用与硬拒绝，任何开关都不放行 |
    | `capability.constraints` | 参数冻结照旧追加 |
    | `scope.target_allowlist` | 目标白名单（硬规则 3） |
    | `scope.network_egress` | 出网闸门（Policy + 沙箱两层） |
    | 协议白名单（http/https） | `PolicyGate` 的 scheme 检查 |

    于是 DSH 会话里的**人**那道闸是：**DSH 的 `approval` 档位**（host 平面）+
    **目标动作裁决**（preset 平面，`ask`/deny，见第 8 条与待办 R-22）。

    **这条不变量已机检**（`tools/dsh_install.py` 的 `verify_gate_consistency`，
    `--check` 默认跑）：**抬起了内核 ask 档 ⇒ host 补丁里至少要有一个
    `approval: ask` 的档位**；三档全 `never` 会被直接报出来。
---

## 九、DSH 升级流程（上游更新后插件不被静默打断）

**两个检查器，分工明确**：

| 检查器 | 管什么 | 什么时候跑 |
|---|---|---|
| `python tools/dsh_install.py --check` | **本侧一致性**：装到 `~/.dsh` 的副本 vs 仓库、roster、审计桥、运行态（进程 vs 文件） | 每次改动 dsh/ 之后 |
| `python tools/dsh_compat_check.py` | **对侧兼容性**：已装 harness 里，我们依赖的包/接口/行/参数还在不在（7 项，见下） | DSH 升级前后、日常抽查 |

`dsh_compat_check` 覆盖的 7 个触面（每一项都对应 `dsh/` 下代码的真实调用点）：

1. **C1 包存在性**——preset 组合 + bridge 引用的 `@deepseek-ai/*` 全部在
   （启用行缺包=FAIL；`disabled` 占位缺包=容忍，不计）
2. **C2 persona API**——`section()/getSectionOrder`、`deployment:persona-prefix/suffix`
   分区名、order 有限数校验
3. **C3 tools-policy API**——`session/event` 事件名、`agentPreset` 归属字段、
   `tools/pre-execute` 裁决钩子派发点
4. **C4 mcp-client schema**——`transport/serverName/command/cwd/env/
   toolCallTimeoutMs/failOnStartupError/streamable-http`
5. **C5 host 补丁目标**——`dsh-base` 组合里 `approval`/`permission` 两行与档位键；
   且我们补丁引用的每个行 id 在 host 里仍存在
6. **C6 CLI 入口**——`apps/cli/lib/bin.js` 存在且含 `--patch/profile`
7. **C7 版本锁**——`dsh/DSH_VERSION.lock` 记录的 harness commit vs 当前 HEAD

**升级五步（顺序不能反）**：

```bash
# 0) 升级前建基线（两边都跑，全绿才动手）
python tools/dsh_install.py --check
python tools/dsh_compat_check.py

# 1) 更新 DSH（git pull / 重装 / 换版本）
# 2) 升级后重跑兼容检查——FAIL 的每一项就是断点，按提示修 preset/插件/补丁
python tools/dsh_compat_check.py

# 3) 修完后冒烟（第五节验证步骤：roster → MCP 拉起 → 真机会话）
# 4) 全绿后更新版本锁（记录新 commit/日期），再跑一次 install check 对齐副本
```

**锁文件**（`dsh/DSH_VERSION.lock`）：记录"被验证过的 harness commit + 日期"。
上游一动，C7 立刻报 WARN——这不是错误，是提醒你按第 2-4 步走一遍。

**设计原则（降低上游耦合，新增集成时遵守）**：能用「配置行」解决的不写插件；
能用「MCP 工具 + persona 提示」解决的不写深钩子；插件一律明确失败语义
（persona fail-loud、tools-policy fail-closed、审计 fail-open）。深钩子
（`session/event`、`tools/pre-execute`）是**高脆弱点**，升级后优先复测它们。
