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
| F1 | **高** | MCP 底层工具入口不过 Policy：`--targets` 白名单与高危授权双双失效，越界目标照常执行 | **已修**（Policy 全入口化，见第九节复测） |
| F2 | 中 | 失败一律报成成功：`isError` 恒为 `false`，`pentest_run` 失败也报成功 | **已修**（失败走 `isError=true` + 结构化错误，见第九节复测） |
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

---

## 九、复测：越界目标已被闸门拒绝（F1 / F2 修复后）

> 复测日期：2026-09-18　　命令与第五节/第四节完全相同的 DSH mcp-client 挂载路径
> （`--targets 127.0.0.1`，`authorize=off`），只把被测代码换成修复后的版本。

### 9.1 修复内容（对应 F1 / F2）

| 项 | 改动 |
|---|---|
| F1 | 新增 `penagent/policy_gate.py`：闸门（目标白名单 + 高危授权 + 协议白名单）由 **`ToolRegistry` 持有**，裁决在 `execute()` 内部、工具体之前——ReAct 循环 / MCP 底层工具 / Web 子进程都绕不过去。原实现只在 `PenAgent.run` 里调 `policy.check`，底层工具分支直连注册表 |
| F1（附带） | `PentestMCPServer` 把 `--targets` 接进闸门；`_agent()`（pentest_run）复用服务端授权目标；新增操作员级 `--authorize`（**调用参数里的 `authorize` 一律不生效**，避免模型自我授权） |
| F2 | MCP 结果按 `ok` / `outcome` 映射到 `isError`；工具异常改走 `isError=true` 的结构化结果，不再用协议级 `error` |

### 9.2 复测输出（全文）

```
XPentest MCP Server 就绪（tools/list 可查工具，targets=127.0.0.1，authorize=off）
[R1] port_scan {"host":"127.0.0.1","ports":"80"}
  isError = false
  content = [{"type":"text","text":"{\"tool\": \"port_scan\", \"ok\": true, \"output\": {\"host\": \"127.0.0.1\", \"open_ports\": []}, \"error\": \"\", \"duration_ms\": 1514}"}]
[R2] port_scan {"host":"127.0.0.2","ports":"80"}
  isError = true
  content = [{"type":"text","text":"Error: {\"tool\": \"port_scan\", \"ok\": false, \"output\": \"\", \"error\": \"目标 '127.0.0.2' 不在授权范围 ['127.0.0.1']\", \"duration_ms\": 0}"}]
[R3] port_scan {"host":"192.168.1.1","ports":"80"}
  isError = true
  content = [{"type":"text","text":"Error: {\"tool\": \"port_scan\", \"ok\": false, \"output\": \"\", \"error\": \"目标 '192.168.1.1' 不在授权范围 ['127.0.0.1']\", \"duration_ms\": 0}"}]
[R4] http_probe {"url":"http://192.168.1.1/admin"}
  isError = true
  content = [{"type":"text","text":"Error: {\"tool\": \"http_probe\", \"ok\": false, \"output\": \"\", \"error\": \"目标 'http://192.168.1.1/admin' 不在授权范围 ['127.0.0.1']\", \"duration_ms\": 0}"}]
[R5] robots_fetch {"url":"http://127.0.0.1/robots.txt"}
  isError = true
  content = [{"type":"text","text":"Error: {\"tool\": \"robots_fetch\", \"ok\": false, \"output\": \"\", \"error\": \"robots_fetch() missing 1 required positional argument: 'base_url'\", \"duration_ms\": 0}"}]
[R6] dns_lookup {"domain":"127.0.0.1"}
  isError = false
  content = [{"type":"text","text":"{\"tool\": \"dns_lookup\", \"ok\": true, \"output\": {\"domain\": \"127.0.0.1\", \"ips\": [\"127.0.0.1\"]}, \"error\": \"\", \"duration_ms\": 2}"}]
```

### 9.3 前后对照

| 用例 | 修复前（第三节 A3 / 第五节） | 修复后（本次） |
|---|---|---|
| `port_scan` 127.0.0.1（白名单内） | `ok: true`，`isError=false`，1510ms | `ok: true`，`isError=false`，1514ms（**未回归**） |
| `port_scan` **127.0.0.2**（白名单外） | `ok: true`，真实扫了 1510ms | **`ok: false` + `isError=true` + `duration_ms: 0`**（没执行） |
| `port_scan` **192.168.1.1**（内网） | `ok: true`，真实发起连接 | **被拒**，`duration_ms: 0` |
| `http_probe` 白名单外 URL | 未测（同类） | **被拒** |
| `robots_fetch` 缺参 | `ok: false` 但 `isError=false` | `ok: false` **且 `isError=true`** |
| `dns_lookup` 白名单内 | `ok: true` | `ok: true`（**未回归**） |

`duration_ms: 0` 是关键证据：拒绝发生在**工具体之前**，不存在"先连再判"。
这一点另有单元测试钉死（`tests/test_policy_gate.py::test_registry_gate_blocks_before_tool_body_runs`
断言工具体一次都没被调用）。

### 9.4 复测中额外发现并修掉的一个 bug（值得单记）

第一次复测时 R2/R3 **仍然执行了**。根因不在闸门，而在**白名单的解析**：

- CLI 的 `--targets` 是**逗号分隔字符串**，`PentestMCPServer` 直接 `list(allowed_targets)`
  → 字符串是 iterable，`list("127.0.0.1")` 炸成 `['1','2','7','.','0','.','0','.','1']`；
- 而白名单匹配用的是 `host.endswith("." + t)`，于是单字符条目开始乱命中：
  条目 `'2'` 命中 `127.0.0.2`、条目 `'1'` 命中 `192.168.1.1`——**白名单等于失效**。

这条在 F1 修复前是隐性的（闸门根本没被调用，轮不到白名单起作用），闸门一接上就暴露了。
CLI 的 `run` 子命令同样把字符串喂给 `Policy`，属同一根因，故修在 `Policy` 层：
新增 `Policy.normalize_targets()`（支持 `"a,b"` 与可迭代对象，空值回落默认回环白名单），
`PentestMCPServer` 一并改用。复测 R2/R3 随即变为拒绝。

回归用例：`tests/test_policy_gate.py::test_policy_normalizes_targets`（7 组参数）与
`::test_cli_style_string_targets_do_not_leak_single_chars`（断言 127.0.0.2 / 192.168.1.1 /
10.0.0.1 全部被拒、127.0.0.1 放行）。

### 9.5 回归

```
有 torch：204 passed（含本次新增 31 例）
无 torch：196 passed, 3 skipped（3 处 importorskip，与原行为一致）
```

---

## 十、真机会话实测（2026-09-21 晚，DSH 0.1.6-alpha.2）

**场景**：从 DSH Web UI 起一个新会话，选「Proteus 千面」，对本地受控靶场
（OWASP Juice Shop，http://127.0.0.1:3000）下达一轮被动信息收集任务，
用浏览器驱动全程观察。**结论：preset 现已真机可用，但模型会绕开内核。**

### 10.1 两个阻断项（都已修）

**F3 · preset 静默消失（DSH 升级所致）**

- 现象：选择器里只有官方四档，没有「Proteus 千面」，**界面上没有任何报错**。
- 根因：本 preset 的 composition 是**旧版 standard preset 的 fork**（0.1.5-rc.2 时代）。
  harness 更新到 0.1.6 后，旧基座引用的 `@deepseek-ai/dsh-workflow-worker-thread`
  等 7 个包已被移除/改名（现为 `dsh-workflow-ptc`），profile 的 node_modules 里
  只剩**断链符号链接**。发现机制据此把 preset 判为 `broken`，而 broken 的 preset
  **不进选择器**。
- 诊断：跑 `discoverPresets`（指南 5.1）——
  `proteus | broken=row "workflow-worker-thread" names a plugin that cannot be resolved`。
- 修复：以当前
  `packages/preset/agent-presets/presets/standard/agent.cordis.yml` 为基座重新合成
  （替换 persona 行、追加 mcp-proteus 行，其余逐字保留），并补上 profile 缺失的
  `dsh-workflow-ptc` 链接。修后 `broken=否`。**基座版本已写进文件头**，并要求
  DSH 升级后先跑 roster。
- 附注：用户另一套 preset `liangshen` 同样 broken（同因），本次未动。

**F4 · 修好后仍需重启 DSH 进程**

- 指南 5.1 写"发现是每次调用重新扫盘的，新写的 preset 不需要重启进程就能被看到"——
  **0.1.6 实测不成立**：roster 在进程启动时挂载（`mounts ONCE under a standing scope`），
  修好的 preset 要在重启 `dsh --profile web` 之后才出现在选择器里。

### 10.2 内核接线（真机验证通过）

- 会话 runtime context 显示 `file policy: workspace-write` + `Approval policy: ask`
  ——host 补丁的 `proteus-standard` 档生效。
- 启动日志：`XPentest MCP Server 就绪（… default_mode=pentest-standard，工具数=40）`
  （带 `--discover-mcp`，含 seckb / chameleon）。
- 用 DSH 自己的 mcp-client 独立挂载（指南 5.3）实测：**注册 `mcp__proteus__*` 28 个**
  （样例：`dalfox_xss` / `dnsx_lookup` / `ffuf_fuzz` / `fscan_scan` / `gobuster_dir` …）。

### 10.3 关键发现：工具装上了，但模型不用（本次最值得处理的一条）

任务执行全程 **12 步、零次 `mcp__proteus__*` 调用**——模型用 DSH 自带的
PowerShell `Invoke-WebRequest` 把整轮侦察做完，最后用宿主的 `write` 工具
在会话工作区落了报告 `recon-report-juiceshop.md`（6KB）。

- **报告质量并不差**：每条发现都有可重放 GET、自行识别了 SPA 兜底页
  （"sitemap.xml 返回 SPA 回退 HTML，不计为发现"——与内核侧第三批技能同源）、
  如实写明"配置转储中无明文密钥"。发现包括 `/ftp` 目录列出、`acquisitions.md`
  机密文档、`incident-support.kdbx` 可下载、`/rest/admin/application-configuration`
  未鉴权返回 23.5KB 全量配置、`/rest/captcha` 直接把 `answer` 一起返回等。
- **但内核全程旁路**：证据链没记、记忆没落、技能没注入、ModeProfile 闸门没起作用
  ——报告是自然语言，不可机验。**这正是内核要解决的问题，却被宿主工具的便利绕过了。**
- 成本：346K tokens、59 tok/s、缓存命中 85%（UI 显示 1 轮 12 步）。

**已做的处置（软约束）**：`prompts/dsh-persona.md` 的"工具使用"段补了硬规则——
对目标的一切网络动作必须走 `mcp__proteus__*`，宿主 shell/文件工具只用于本地操作；
并写入本次实测教训与"若确需宿主工具，须先说明理由并标注该步不经内核校验"。

**仍未机制化（留给决策）**：软约束违背项目硬规则 1（约束要机制性生效，不靠模型自觉）。
可选机制化路径：① 在 preset 里 `disabled: true` 掉 DSH 的 pwsh/bash 行（代价：本地
解压/脚本能力也没了，而 preset 的设计初衷正需要它们）；② 宿主侧对 shell 加网络出口
策略（DSH 是否支持待查）；③ 接受"DSH 会话存在旁路"并写进文档，把内核价值限定在
显式使用 `mcp__proteus__*` 或 `pentest_run` 的路径上。
### 10.4 补记：模型的拒绝理由（值得记下来）+ 档位机制验证

**模型为什么不用内核工具**（会话第 2 轮里它自己给出的理由，逐条成立）：

1. **纪律约束**：任务限定"不发载荷、不爆破、不高频"，而 `nuclei_scan` /
   `sqlmap_auto` / `dalfox_xss` / `ffuf_fuzz` / `gobuster_dir` / `fscan_scan` /
   `pf_*` 本质是主动攻击/爆破/模板扫描器，会违反约束；剩下的轻量工具够不够用是另一回事。
2. **链路不成立**：chameleon 系与 `pentest_run` 走**远端采集桥/代理**（带
   `proxy_region`），对 `127.0.0.1:3000` 这种本机回环目标，远端代理看不到被扫端——
   这是**内核侧的能力缺口**，不是模型的偏好问题。
3. **证据精度**：任务要求"状态码 + 响应头 + 可重放证据"，pwsh 的
   `Invoke-WebRequest` 能给原始响应头（判读 `Server`/`X-Powered-By` 为空）、
   能读完整正文并用 `Content-Type` 严格区分 SPA 回退与真实端点；内核单点工具
   （`http_probe` / `robots_fetch`）的固定输出格式给不了这些精细判读。
4. **可审计性**：单一脚本、30 余次请求统一节流与统一判读逻辑，比拼装多个单点
   工具更干净。

结论要跟着证据走：**这更像"内核在该场景确实不划算"，而不是"模型不会用工具"**。
所以 persona 的规则改成"优先走内核 + 三种允许例外（链路到不了 / 重型扫描器不
符合任务纪律 / 证据精度需要原始响应控制），例外要说明理由并标注该步不经内核校验"，
而不是一刀切"必须走内核"。

**档位机制验证（三档 → 实测两档）**：

| 档位 | 会话 runtime context | 写文件实测 |
|---|---|---|
| `proteus-standard` | `file policy: workspace-write` + `Approval policy: ask` | 正常落盘（本轮报告即由此写出） |
| `proteus-safe` | `file policy: read-only` + `Approval policy: ask` | 直接写 → **`FS_SANDBOX_DENIED`**；模型按提示发起一次性提权（`sandbox_permissions: workspace-write` + 理由）→ UI 弹审批 → **拒绝后写入未发生**，模型如实说明 |

即：**档位是机制性生效的**（沙箱拒绝发生在工具执行前，提权要人工审批），
模型也正确走了"拒绝 → 提权申请 → 被拒后如实收口"的路径。`proteus-ctf`
（`danger-full-access` + `approval: never`）未实测。

> **后续（方案评估）**：本文第十节暴露的"L1 能力 / L2 机制 / L3 审计"三层问题，
> 以及"preset 行 vs 完整插件"的能力边界与三步走建议，见
> `docs/DSH插件化与内核旁路治理.md`。
