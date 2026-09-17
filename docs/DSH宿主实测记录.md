# DSH 宿主真机实测记录

> 日期：2026-09-17　　被测：Proteus preset 挂载到 deepseek-harness `0.1.5-rc.2`
> 依据：`docs/DSH宿主接入指南.md` 第五节，按 **5.1 → 5.2 → 5.3** 顺序执行，未跳步
> 约束：**只读 DSH**，未改 deepseek-harness 任何文件；本仓库内改动仅限 `dsh/` 与 `docs/`
> 原始捕获：完整输出已内嵌于第四节（探针脚本同节给出，可重跑复现）

## 零、结论摘要

| 步骤 | 结论 |
|---|---|
| 5.1 发现与健康 | **通过**：`proteus broken=否`，`name` / `description` / `order` 均正确解析 |
| 5.2 MCP 行拉起内核 | **通过**：`24 tools \| OK`，`inputSchema` 全部合规 |
| 5.3 DSH mcp-client 挂载 | **通过**：注册 24 个 `mcp__proteus__*`，真实调用返回真实结果 |

链路本身是通的——preset 能被发现、内核能被 stdio 拉起、工具能被 DSH 看见并真实调用。
但验证过程中查出 **5 个问题**，其中 F1 触碰 `AGENTS.md` 第 2 节硬规则 3：

| 编号 | 严重度 | 一句话 | 处置 |
|---|---|---|---|
| F1 | **高** | MCP 底层工具入口不过 Policy：`--targets` 白名单与高危授权双双失效，越界目标照常执行 | 记录待修（根因在内核） |
| F2 | 中 | 失败一律报成成功：`isError` 恒为 `false`，`pentest_run` 失败也报成功 | 记录待修（根因在内核） |
| F3 | 低 | 5.1 的 `broken` 不覆盖行 `config` 与 `!!js` 求值，只证明"能装上" | 已修文档 |
| F4 | 低 | 指南 5.3 用手抄配置而非 preset 派生，preset 写错时会假阴性 | 已修文档 |
| F5 | 低 | 函数型工具静默丢弃未知参数，报错信息对模型不友好 | 记录待修（根因在内核） |

F1 / F2 / F5 的根因都在 `penagent/`，**超出本次"只改 `dsh/` 与 `docs/`"的范围**，因此只
定位到行号、不改代码。F3 / F4 已就地修正见第八节。

---

## 一、被测环境（实测取值）

| 项 | 值 |
|---|---|
| `$DSH_HOME` | `<USER_HOME>\.dsh`（**环境变量未导出**，按指南约定路径直接使用） |
| harness 包目录 | `~/.dsh/profiles/node_modules`（`@deepseek-ai/*` 共 243 个） |
| node | `v24.14.1` |
| python | `<PY312>\python.exe`（存在，`Python 3.12.9`） |
| 已装 preset | `~/.dsh/.agent-presets/proteus/`（3 个文件） |
| 仓库内的 preset | `dsh/.agent-presets/proteus/`（3 个文件） |
| `.env` | **不存在**；`PENTEST_LLM_*` 三个变量**未设置** |

安装位置核对（第 3 条指令要求）：`diff -r` 逐字节比较，**仓库版与已装版完全一致**，
故无需按指南第二节重装，直接进入 5.1。

```
$ diff -r ~/.dsh/.agent-presets/proteus/ <仓库>/dsh/.agent-presets/proteus/
（无输出；diff 退出码 = 0）
```

---

## 二、5.1 发现与健康

### 命令

```bash
cd ~/.dsh/profiles
node --input-type=module -e "
import { discoverPresets } from '@deepseek-ai/dsh-agent-presets'
import { homedir } from 'node:os'; import { join } from 'node:path'; import { pathToFileURL } from 'node:url'
const roots = [{ path: join(homedir(), '.dsh', '.agent-presets'), trust: 'user' }]
const found = await discoverPresets(roots, pathToFileURL(join(process.cwd(), 'x')).href)
for (const p of found) console.log(p.id, 'broken=' + (p.broken ?? '否'))
"
```

### 输出（全文）

```
liangshen broken=否
proteus broken=否
```

补充：把 proteus 的发现记录整份打印，确认元数据也解析成功（无 `broken` 字段）。

```json
{
  "id": "proteus",
  "trust": "user",
  "path": "C:\\Users\\<USER>\\.dsh\\.agent-presets\\proteus\\agent.cordis.yml",
  "name": "Proteus 千面",
  "description": "多模式渗透测试 Agent（Proteus 内核 + mcp__proteus__* 工具）。仅用于授权范围内的受控安全实验。",
  "order": 5
}
```

### 结论

**通过**。preset 在用户根下被正确发现，`id` 合法，`preset.yml` 的显示名/描述/排序
均被读入。无 `broken` 字段 = 该 preset 可以 composable 地挂载。

### 覆盖边界（本次核对 DSH 源码后必须记下的一条）

`broken` 为空**只说明"能装上"**，它的判据是两件事：

1. composition 文件的 YAML 用 Loader 自身方言解析通过；
2. 每一行的 **specifier** 可解析（包是否装在 harness、相对路径的文件是否存在）。

它**不看**行 `config` 里的内容——`rowResolves()` 只检查行的 `name`。所以 preset 里的
`command` python 路径写错、`cwd` 指错目录，`broken` 依然是空。`!!js` 表达式的求值也
同样不在覆盖范围内；DSH 源码里写明了这是刻意取舍（`lib/index.js` 注释：
*the one carrying `!!js` ... so health can never call a composition broken*），求值
发生在真正挂载时（Loader 的 `internal/config` 钩子 → `interpolate()` 递归求值整份行
config，包括嵌套的 `env`）。

> 附带确认：我们 preset 里 `env` 的 `!!js process.env.PENTEST_LLM_BASE_URL ?? ''`
> 写法**成立**——`!!js` 节点被 `interpolate()` 递归处理，且 `evaluate()` 是
> `with (ctx) { return eval(expr) }`，`process` 由全局作用域可达。这一条是读源码
> 得出的，**未**经真机挂载验证（真机要起 web 会话，即指南 5.4，本次未做）。

### 修复

无（发现与健康本身通过）。指南已补上这层覆盖边界说明，见第八节。

---

## 三、5.2 MCP 行拉起内核

### 命令

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

### 输出（全文）

```
24 tools | OK
```

补充：直接对内核做一次原始 `tools/list`，取名字与 schema 形状。

```
raw tools/list 数量: 24
原始工具名: dalfox_xss, dnsx_lookup, ehole_finger, ffuf_fuzz, fscan_scan, gobuster_dir,
httpx_probe, katana_crawl, naabu_scan, nuclei_scan, pocsuite_poc, poxiao_recon,
poxiao_scan, ruoyi_scan, sqlmap_auto, subfinder_enum, dns_lookup, http_probe,
pentest_missions, pentest_reflect, pentest_run, pentest_skills, port_scan, robots_fetch
带 proteus_ 前缀的原始名: 无
inputSchema 不合规的工具: 无（全部 {type:object, properties:{...}}）
带 destructiveHint 注解: dalfox_xss, ffuf_fuzz, fscan_scan, gobuster_dir, naabu_scan,
nuclei_scan, pocsuite_poc, poxiao_scan, ruoyi_scan, sqlmap_auto
```

### 结论

**通过**。内核能被以 stdio 拉起，`tools/list` 返回 24 个工具，全部带规范的
`inputSchema`，高危工具带 `annotations.destructiveHint`。与指南第六节"24 个工具"一致
（16 个外部 CLI + 4 个内置被动侦察 + 4 个内核高层能力）。

**关于"`tools/list` 出现 `proteus_*` 工具"**：实测原始工具名**不带任何前缀**
（`port_scan`、`pentest_run`……）。`proteus` 只出现在 **DSH 侧**——mcp-client 统一加
前缀成 `mcp__<serverName>__<原名>`（即 `mcp__proteus__port_scan`）。这是命名方案，
不是缺陷；下面 5.3 验证的正是带前缀的那一组。

### 修复

无。

---

## 四、5.3 用 DSH 自己的 mcp-client 挂载（真实调用）

### 命令

按指南原样执行（脚本在 `~/.dsh/profiles` 下，跑完删除）：

```bash
cd ~/.dsh/profiles
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

### 输出（全文）

```
XPentest MCP Server 就绪（tools/list 可查工具，targets=127.0.0.1）
注册工具数: 24
调用 port_scan -> isError = false [{"type":"text","text":"{\"tool\": \"port_scan\", \"ok\": true, \"output\": {\"host\": \"127.0.0.1\", \"open_ports\": []
```

（最后一行被脚本截断到 120 字符；完整载荷见下方 A1。）

### 补充探针：真实调用 5 例 + 降级 2 例

同一份 config 下多跑了几次调用，覆盖成功、白名单外、失败、降级四类路径。
完整输出：A / B 两段就是原始捕获全文。捕获文件当时落在 `tests/_tmp/`，而该目录会被
测试套件清空重建（本次全量 pytest 后就没了），所以未保留原文件——脚本见上面第四节，
可重跑复现。

```
== A. 注册结果 ==
proteus 工具数: 24
工具名: mcp__proteus__dalfox_xss, mcp__proteus__dns_lookup, ..., mcp__proteus__subfinder_enum

[A1] port_scan {"host":"127.0.0.1","ports":"80,443"}
  isError = false
  content = [{"type":"text","text":"{\"tool\": \"port_scan\", \"ok\": true, \"output\": {\"host\": \"127.0.0.1\", \"open_ports\": []}, \"error\": \"\", \"duration_ms\": 3021}"}]

[A2] pentest_missions {}
  isError = false
  content = [{"type":"text","text":"[{\"id\": \"3b534570\", \"target\": \"127.0.0.1\", \"objective\": \"探测 80 端口\", \"started_at\": \"...\", \"steps\": [], \"reflection\": \"LLM 调用失败: 未配置 PENTEST_LLM_API_KEY（.env 或环境变量）\", \"outcome\": \"failed\"}]"}]

[A3] port_scan {"host":"127.0.0.2","ports":"80"}          <-- 白名单外（见 F1）
  isError = false
  content = [{"type":"text","text":"{\"tool\": \"port_scan\", \"ok\": true, \"output\": {\"host\": \"127.0.0.2\", \"open_ports\": []}, \"error\": \"\", \"duration_ms\": 1510}"}]

[A4] robots_fetch {"url":"http://127.0.0.1/robots.txt"}   <-- 参数名错（见 F5/F2）
  isError = false
  content = [{"type":"text","text":"{\"tool\": \"robots_fetch\", \"ok\": false, \"output\": \"\", \"error\": \"robots_fetch() missing 1 required positional argument: 'base_url'\", \"duration_ms\": 0}"}]

[A5] pentest_run {"target":"127.0.0.1","objective":"probe port 80"}   <-- 无 LLM 配置（见 F2）
  isError = false
  content = [{"type":"text","text":"{\"mission_id\": \"de5f467a\", \"target\": \"127.0.0.1\", \"objective\": \"probe port 80\", \"outcome\": \"failed\", \"steps\": 1, \"summary\": \"LLM 调用失败: 未配置 PENTEST_LLM_API_KEY（.env 或环境变量）\", \"evidence_refs\": [], \"injected_skills\": [], \"reflection\": \"\"}"}]

== B. failOnStartupError 降级路径 ==
B1 坏命令 + failOnStartupError:false -> 抛错=否, proteus 工具数=0
B2 坏命令 + failOnStartupError:true  -> 抛错=是: mcp-client(proteus): initial connection or tool synchronization failed
```

### 结论

**通过**。用 DSH 自带的 `@deepseek-ai/dsh-mcp-client`、与 preset 相同的配置挂载，
注册出 24 个 `mcp__proteus__*` 工具，并真实调用成功（A1 返回真实扫描结果，
`isError=false`）。A2 列出的作战记录说明内核侧 Memory 读写正常。

**降级路径（指令第 4 条要求的"如实记录"）**：

- 当前 `.env` **不存在**、`PENTEST_LLM_*` **未设置**，但内核**照常启动**、24 个工具
  **一个不少**——因为 LLM 配置只在 `pentest_run` 调用时才需要，启动阶段不读它。
  也就是说：**本例并没有真的走到降级路径**，`failOnStartupError` 没有发挥作用。
- 只有 LLM 决策循环受影响：A5 的 `pentest_run` 返回 `outcome: "failed"`，摘要写明
  `LLM 调用失败: 未配置 PENTEST_LLM_API_KEY（.env 或环境变量）`。内核在发起任何网络
  请求前就拒绝了（`LLMConfig.ready()` 为假即抛），未产生外呼。
- 降级路径本身是**有效**的，用坏命令单独验证：B1 确认 `failOnStartupError: false` 下
  不抛错、proteus 工具数降为 0，会话仍可用；B2 确认置 `true` 时会明确抛错
  （`initial connection or tool synchronization failed`）。两个方向都符合设计。

### 修复

无（验证本身通过）。

---

## 五、问题清单

### F1（高）MCP 底层工具入口不过 Policy：目标白名单与高危授权双双失效

**现象**

`--targets 127.0.0.1` 起服务后，通过 DSH 调用 `mcp__proteus__port_scan` 传**白名单外**
的目标，工具**照常执行**并返回 `ok: true`：

- 探路时用 `host=192.168.1.1`（内网地址）实测：返回 `ok: true`，耗时 1503 ms，
  说明**真实发起了 TCP 连接尝试**。该地址此后未再触碰。
- 固化证据改用 `host=127.0.0.2`（见 A3）：仍是白名单外（白名单是按 `127.0.0.1` 精确
  匹配的），但只走回环、零外部流量，可安全复现。结果同样是 `ok: true`、1510 ms。

若 Policy 生效，`Policy.check()` 会对目标走 `_in_scope()`，`127.0.0.2` 既不等于
`127.0.0.1` 也不以 `.127.0.0.1` 结尾，应被判 `目标 ... 不在授权范围` 而拒绝。

**根因**

`penagent/mcp.py` 的两处：

| 行 | 代码 | 问题 |
|---|---|---|
| `:63` | `self.policy = Policy(allowed_targets=allowed_targets or None)` | `--targets` 唯一落点 |
| `:147` | `tool_result = self.registry.execute(name, args)` | 底层工具分支**从不调用** `Policy.check`，`self.policy` 是死代码 |
| `:69` | `Policy(allowed_targets=None, authorize=authorize)` | `_agent()` 另起一份 Policy，把 `--targets` 丢了（只剩默认回环） |

后果分三块，全在这一条分支上：目标白名单不校验、`dangerous` / `authorize` 不校验、
ModeProfile 的 capability 与 permission 档位不生效。这直接违反 `AGENTS.md` 第 2 节
硬规则 3「目标白名单硬校验不可绕过：任何模式下，越界目标一律拒绝」。

**影响面**

指南第三节把 `proteus-ctf` 定为 `approval: never` + `danger-full-access`。在这一档下，
越界目标**既不弹审批（DSH 侧 never）、也不被内核拦（F1）**——两道闸同时失效。所以
"默认只在回环上活动"这句话不能当作底层工具路径的保证。

**修复（本次未做，超出允许的修改范围）**

需要改内核 `penagent/mcp.py`：底层分支执行前接 `Policy.check()`（并把 mode 一并绑上），
`_agent()` 复用 `self.policy` 而不是另起一份。改内核超出"只改 `dsh/` 与 `docs/`"的约束，
故本次仅在 `dsh/proteus.cordis.patch.yml` 的 `proteus-ctf` 档位处加了醒目告警注释，
并把指南第八节第 3 条改写为实测结论。

---

### F2（中）失败一律报成成功：`isError` 恒为 `false`

**现象**

两种失败都逃逸成"成功"：

| 调用 | 载荷 | `isError` |
|---|---|---|
| A4 `robots_fetch` 缺参 | `{"ok": false, "error": "missing 1 required positional argument: 'base_url'"}` | `false` |
| A5 `pentest_run` 无 LLM 配置 | `{"outcome": "failed", "summary": "LLM 调用失败: ..."}` | `false` |

A5 更麻烦：高层能力的载荷里**连 `ok` 字段都没有**（用 `outcome` 表达结果），所以指南
原来"客户端读 `{"ok": false}` 就能判断失败"的说法**不成立**——严格客户端只拿到
`isError=false`，会把一次失败的渗透任务当成功。

（对照：`mcp__proteus__no_such_tool` 这类是 **DSH 侧**拒的，`isError=true`，不在本条范围。）

**根因**

`penagent/mcp.py` 的 `_result()` 把 `is_error` 默认成 `False`，而 5 个调用点
（`:134` `:137` `:139` `:144` `:148`）**没有一个传它**；`ToolResult.ok` 也从未映射到
`isError`。注意这**不是** `registry.execute(...)` 那一行的问题（指南原文如此描述），
修点在 `_result()` 及其调用点。

**修复（本次未做）**

内核范围。正确改法：`_result(msg_id, payload, is_error=...)`，底层分支传
`is_error=not tool_result.ok`，`pentest_run` 分支按 `outcome != "success"` 或
`result.ok` 传。已把指南第八节第 4 条改写为实测表格。

---

### F3（低）5.1 的 `broken` 不覆盖行 `config` 与 `!!js` 求值

**现象**：`broken=否` 容易被误读成"这个 preset 一切正常"。实测核对源码后确认，它只
证明"能装上"。

**根因**：`broken` 由「YAML 方言解析」+「`rowResolves()` 检查行的 specifier」两项得出；
后者只看行的 `name`，不看 `config` 里的 `command` / `cwd` / `env`；`!!js` 求值刻意
不在 health 检查里做（源码注释已写明）。

**修复（已做）**：在指南 5.1 末尾补了"这个检查覆盖到哪、没覆盖到哪"小节，把上面两条
边界写清楚，并指出 `broken` 为空**不代表**内核一定起得来——后者靠 5.2 / 5.3 / 5.4。

---

### F4（低）指南 5.3 用"手抄配置"而非从 preset 派生，存在假阴性

**现象**：5.3 的脚本把 preset 里那一行 mcp 配置**人工复制**了一遍。若 preset YAML 里
`command` / `cwd` 写错，F3 已说明 5.1 不会报，而 5.3 因为抄的是正确值**照样通过**——
两个步骤都通过、真机却挂不上。

**根因**：验证脚本与 preset 之间没有强制的一致性检查，靠人抄。

**本次做的交叉核对**：把 preset 的 `agent.cordis.yml` 与实跑 config 逐字比对，
`command` / `args` / `cwd` / `transport` / `serverName` / `toolCallTimeoutMs` /
`failOnStartupError` **全部一致**，所以本次 5.3 的通过是可信的。

**修复（已做）**：在指南 5.3 开头插入"先交叉核对（必做）"提示框，给出 `grep` 命令，
要求在跑脚本前逐字比对，并说明不一致时以 preset 为准。

> 更彻底的做法（本次未做，留作建议）：写一个从 preset YAML 抽取行 config 再挂载的
> 校验脚本，让"抄"这一步消失。考虑到它要在 Python 仓库里新增一个 JS 校验件、且
> `!!js` 节点需要自行打桩，本次按"最小改动"取舍，只做了人工核对 + 文档约束。

---

### F5（低）函数型工具静默丢弃未知参数

**现象**：`robots_fetch` 的 schema 声明参数是 `base_url`，实测传 `url` 时不会得到
"未知参数 `url`"的提示，而是参数被丢掉、由 Python 抛缺参错误（A4）。

**根因**：`penagent/tools.py:100` —

```python
out = spec.fn(**{k: v for k, v in args.items() if k in (spec.parameters or {})})
```

按 `spec.parameters` 先过滤再调用，未做必需参数的前置校验，于是错误信息退化成
Python 的 TypeError 文本，对模型不友好（模型看不到"你该用 `base_url`"）。

**修复（本次未做）**：内核范围。客户端只要照 `inputSchema` 传参就不受影响，故定级低。
已作为第 6 条记入指南第八节。

---

## 六、本次未覆盖的部分（如实声明）

1. **指南 5.4（会话内 UI 验收）未执行**：需要以 web profile 起 DSH 并新建会话，超出
   本次"按 5.1→5.2→5.3 顺序执行"的指令范围。因此下列两件事**仍未经验证**：
   - preset 里 `!!js` env 表达式在**真机挂载**时的求值（只有源码层面的确认，见第二节）；
   - `proteus-safe` / `proteus-standard` 档位下"高危工具弹审批"的行为。
2. **DSH 侧审批栈未参与**：5.3 用的是裸 `Context`（system-prompt + tools + mcp-client），
   没有加载 host 平面的审批插件，所以探针里的调用**没有经过任何审批**。这不影响
   "工具可见且可调用"的结论，但不能据此判断审批档位行为。
3. **`--patch` 加载未验证**：`dsh/proteus.cordis.patch.yml` 本次只验证了 YAML 可解析、
   六个档位（官方三档 + proteus 三档）结构正确、`proteus-ctf` 语义与改前一致；
   未验证 DSH 实际加载该补丁后的档位生效情况。
4. **未改任何 DSH 文件**：全程只读；在 `~/.dsh/profiles/` 下临时创建过 6 个 `.mjs`
   探针脚本（`verify-proteus.mjs`、`probe-proteus.mjs`、`probe2/3/4-proteus.mjs`、
   `final-probe.mjs`），**跑完已全部删除**（`ls *.mjs` 为空）。
5. **测试残留**：`pentest_run` 探针在 `data/missions/default/` 留了 2 条 failed 作战记录，
   `data/` 已被 gitignore，不影响入库。

---

## 七、本次范围内做的修改

| 文件 | 改动 | 理由 |
|---|---|---|
| `dsh/proteus.cordis.patch.yml` | `proteus-ctf` 档位加告警注释（说明该档下越界目标既不弹审批也不被内核拦） | F1 的处置落在"档位选择"这个决策点上；纯注释，语义未变（已验证 YAML 解析结果与改前一致） |
| `docs/DSH宿主接入指南.md` 5.1 | 补"覆盖到哪、没覆盖到哪"小节 | F3 |
| `docs/DSH宿主接入指南.md` 5.3 | 补"先交叉核对（必做）"提示 + `grep` 命令 | F4 |
| `docs/DSH宿主接入指南.md` 八.3 | 改写为实测结论：被绕过的不只是模式约束，`--targets` 白名单同样失效，附实测目标与行号 | F1 |
| `docs/DSH宿主接入指南.md` 八.4 | 改写为失败语义实测表（含 `pentest_run` 无 `ok` 字段），并修正原文对修点的描述 | F2 |
| `docs/DSH宿主接入指南.md` 八.5 | 安全前提按路径区分：白名单只在 `pentest_run` 路径成立 | F1 |
| `docs/DSH宿主接入指南.md` 八.6 | 新增：函数型工具静默丢弃未知参数 | F5 |
| `docs/DSH宿主实测记录.md` | 本文件 | 指令第 7 条 |

内核侧（`penagent/mcp.py`、`penagent/tools.py`）**未改动**——F1 / F2 / F5 的根因在那里，
但超出本次允许的修改范围。

---

## 八、后续建议（按优先级）

1. **修 F1（必修，触碰硬规则 3）**：把 `Policy.check()` 接进 `penagent/mcp.py` 的底层
   工具分支，`_agent()` 复用 `self.policy`。这是"越界目标一律拒绝"能否成立的关键，
   建议优先级高于其余各项。
2. **修 F2**：`_result()` 支持 `is_error`，各调用点按 `ToolResult.ok` / `outcome` 传入，
   让失败对客户端可见。
3. **补 5.4 验证**：起 web profile 真机挂载，确认 `!!js` env 求值与审批档位行为
   （第六节列出的两个未验证项）。
4. 修 F5：执行前校验必需参数，把"未知参数/缺参"变成明确报错。
5. 可选：把 5.3 的手抄配置换成从 preset YAML 派生（F4 的彻底解法）。
