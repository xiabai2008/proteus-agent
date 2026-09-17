# DSH 宿主接入指南（方案 D）

> 把 Proteus 内核挂载为 deepseek-harness 的 agent-preset：**只配置，不改 DSH 核心代码**。
> 适用 DSH 版本：`0.1.5-rc.2`（本机 `$DSH_HOME` = `<USER_HOME>\.dsh`）
> 接入日期：2026-09-17

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
│   ├── .agent-presets/proteus/
│   │   ├── agent.cordis.yml        # preset 本体：persona + MCP 工具
│   │   ├── proteus-persona.mjs     # 随 preset 的本地插件：读取人格文件并注册分区
│   │   └── preset.yml              # 显示名/描述/排序
│   └── proteus.cordis.patch.yml    # host 平面补丁：审批档位绑定
└── prompts/dsh-persona.md          # 宿主侧人格提示词（persona 的唯一来源）
```

安装到 DSH home（`$DSH_HOME` = `<USER_HOME>\.dsh`）：

```bash
mkdir -p ~/.dsh/.agent-presets/proteus
cp dsh/.agent-presets/proteus/{agent.cordis.yml,proteus-persona.mjs,preset.yml} \
   ~/.dsh/.agent-presets/proteus/
```

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

```bash
cd <WS>/deepseek-harness
node apps/cli/lib/bin.js --profile web --patch <REPO>/dsh/proteus.cordis.patch.yml
```

启动后终端会打印带 token 的地址（本机实测为 `http://127.0.0.1:4080/?token=...`）。
在会话的 preset 选择器里选 **「Proteus 千面」**（`order: 5`），新会话即挂载本 preset。

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

实测（本机）：**24 个工具**，公开名一律 `mcp__proteus__<原名>`。

| 类别 | 工具 |
|---|---|
| 高层能力（内核驱动） | `pentest_run` / `pentest_skills` / `pentest_missions` / `pentest_reflect` |
| 内置被动侦察 | `port_scan` / `http_probe` / `dns_lookup` / `robots_fetch` |
| 外部 CLI（本机已安装的才注册） | `poxiao_scan` / `poxiao_recon` / `ruoyi_scan` / `nuclei_scan` / `httpx_probe` / `fscan_scan` / `subfinder_enum` / `dnsx_lookup` / `katana_crawl` / `naabu_scan` / `dalfox_xss` / `sqlmap_auto` / `gobuster_dir` / `ffuf_fuzz` / `ehole_finger` / `pocsuite_poc` |

工具清单来自内核的统一注册中心（`penagent/registry.py`）：新增工具改配置即可，
内核与宿主两侧都不用改代码。

---

## 七、排查

| 现象 | 原因与处置 |
|---|---|
| 选择器里没有 proteus | 目录名不合法（须 `[a-z0-9][a-z0-9-]*`）或没放进 `$DSH_HOME/.agent-presets/`；跑 5.1 看 roster |
| roster 显示 broken | composition 的 YAML 或行解析失败，`broken` 字段会写明是哪一行、哪个 specifier |
| 会话里没有 `mcp__proteus__*` | 内核没起来。`failOnStartupError: false` 会让 preset 照常挂载，只是少这组工具——按 5.2 单独验证命令；常见原因是 `command` 里的 python 路径失效或 `cwd` 不对 |
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
3. **模式与 DSH 审批是两套闸**：DSH 侧审批（host 平面）管"这次调用要不要批准"，
   内核侧 ModeProfile 管"这个工具在该模式下是否可见/可执行、参数冻结、预算与判定器"。
   **但内核的 MCP 底层工具入口目前仍直连注册表、未过 Policy**（阶段一验收报告已列为遗留项），
   因此通过 `mcp__proteus__<底层工具>` 直接调用时，只受 DSH 审批约束；
   走 `mcp__proteus__pentest_run` 才完整经过内核的模式与护栏。
4. **一处未做到位的规范细节**：内核 MCP server 的底层工具分支在**失败**时，
   结果里的 `isError` 仍为 `false`（失败信息在文本载荷的 `{"ok": false, "error": ...}` 里，
   客户端可读）。修它需要在 `registry.execute(...)` 那一行附近改动，而该行反复被本机
   安全扫描误判为「SQL 注入」拦截，故暂缓；不影响工具可见与成功调用。
5. **安全前提**：默认目标白名单仅 127.0.0.1/localhost；仅用于授权范围内的受控安全实验。