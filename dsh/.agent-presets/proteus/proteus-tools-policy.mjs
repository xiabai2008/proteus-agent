/**
 * dsh-proteus-bridge —— 把 DSH 会话里的工具调用写进 spool，供内核侧导入证据链。
 *
 * 设计取舍（对应 docs/DSH插件化与内核旁路治理.md 第二步）：
 *
 * 1. **只读观测**：只订阅 `session/event`，不参与 allow/deny、不改工具结果。
 *    裁决留给第三步（`tools/pre-execute`），且要先保证内核工具够用——
 *    否则"强制走内核"会把会话推向更差的工具。
 * 2. **不在插件里做哈希链**：链式哈希是内核 `penagent/evidence.py` 的唯一实现
 *    （硬规则 2），插件只落原始事件，由内核侧 `python -m penagent dsh-sync`
 *    导入——避免同一套语义两份实现。
 * 3. **fail-open**：写 spool 失败不抛异常、不阻断会话，只在控制台留痕。
 *    审计通道坏掉不该让任务失败；缺的痕迹在 `dsh-sync` 的统计里能看到。
 * 4. 载荷裁剪：args / output 各截断到 MAX_TEXT 字符——审计要的是"发生过什么"，
 *    不是把大正文灌进日志。
 * 5. **内核缺位守卫**（2026-09-22 加）：MCP 行配的是 `failOnStartupError: false`，
 *    内核起不来时 preset 照常挂载、只是**没有那组工具**。那种会话里"对目标发请求"
 *    既没有模式闸门也没有证据链，放行就是"为能用而放弃保护"——所以内核缺位时
 *    目标动作按 `kernelGuard` 收紧（缺省 deny，可 warn / off）。
 */

import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

/** Cordis 诊断用的插件名。 */
export const name = 'proteus-bridge'

/** 单个字段的截断上限（字符）。 */
const MAX_TEXT = 4000

/** 内核工具前缀：MCP serverName=proteus → `mcp__proteus__<tool>`。 */
const KERNEL_TOOL_PREFIX = 'mcp__proteus__'

/** 不注入任何服务：只订阅事件，保持零依赖、零权限面。 */
export const inject = []

function clip(value, limit = MAX_TEXT) {
  let text
  if (typeof value === 'string') text = value
  else if (value === undefined || value === null) return ''
  else {
    try {
      text = JSON.stringify(value)
    } catch {
      text = String(value)
    }
  }
  if (typeof text !== 'string') return ''
  return text.length > limit
    ? `${text.slice(0, limit)}…(+${text.length - limit})`
    : text
}

/**
 * 从 tool/result 的 `message` 里抽正文。
 *
 * 不硬编码 `ToolResultMessage` 的内部形状（DSH 是 pre-stable，形状变过）：按
 * 已知的几种承载方式依次尝试（字符串 / block.text / block.content 字符串或块数组），
 * 都不成立就退回整段 JSON——失败也要留痕。
 */
function resultText(message) {
  try {
    const block = Array.isArray(message?.content)
      ? message.content[0]
      : message?.content
    if (typeof block === 'string') return clip(block)
    if (typeof block?.text === 'string') return clip(block.text)
    const inner = block?.content
    if (typeof inner === 'string') return clip(inner)
    if (Array.isArray(inner)) {
      const parts = inner
        .map((b) => (typeof b === 'string' ? b : b?.text))
        .filter((t) => typeof t === 'string' && t !== '')
      if (parts.length > 0) return clip(parts.join('\n'))
    }
    return clip(message)
  } catch {
    return ''
  }
}

function resultIsError(data) {
  if (data?.error) return true
  const block = Array.isArray(data?.message?.content)
    ? data.message.content[0]
    : data?.message?.content
  return block?.isError === true
}

/**
 * 从 tool/result 的载荷里取 callId。
 *
 * **实测教训（2026-09-21）**：`tool/result` 的事件 data 顶层**没有** `callId`
 * （那是 `tool/call` 的字段）。真机跑完发现结果行 callId 全空、配对只能靠
 * turn/step 兜底。类型定义在 `@deepseek-ai/dsh-llm` 的 message.ts：
 * `ToolResultMessage.source = { kind: 'tool', callId }` —— 正确位置是
 * `message.source.callId`。三级探测是为了抗形状变化：顶层 → source → block。
 */
function resultCallId(data) {
  const direct = data?.callId
  if (direct !== undefined && String(direct) !== '') return String(direct)
  const fromSource = data?.message?.source?.callId
  if (fromSource !== undefined && String(fromSource) !== '') {
    return String(fromSource)
  }
  const block = Array.isArray(data?.message?.content)
    ? data.message.content[0]
    : data?.message?.content
  const fromBlock = block?.callId
  return fromBlock === undefined ? '' : String(fromBlock)
}

/** 网络动词：命中即认为这条 shell 命令在对目标发请求。 */
const NETWORK_VERBS = [
  'curl', 'wget', 'iwr', 'invoke-webrequest', 'invoke-restmethod',
  'ncat', 'netcat', 'telnet', 'ssh', 'nmap', 'masscan', 'nikto',
  'httpx', 'nuclei', 'sqlmap', 'ffuf', 'gobuster', 'dalfox', 'naabu',
  'fscan', 'whatweb', 'wpscan', 'hydra', 'hping3', 'nslookup',
]

const URL_RE = /https?:\/\/[^\s"'`|;)<>]+/gi
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const HOST_FLAG_RE = /(?:--host|--url|--target|-host|-u|-h)\s+([^\s"']+)/gi

function hostOf(urlish) {
  try {
    const withScheme = /^https?:\/\//i.test(urlish) ? urlish : `http://${urlish}`
    return new URL(withScheme).hostname
  } catch {
    return ''
  }
}

/** 从命令文本里抽候选目标主机（小写去重）；没有 URL/主机参数时退回裸 IP。 */
function targetsIn(command) {
  const found = new Set()
  for (const m of command.matchAll(URL_RE)) {
    const host = hostOf(m[0])
    if (host !== '') found.add(host.toLowerCase())
  }
  for (const m of command.matchAll(HOST_FLAG_RE)) {
    const host = hostOf(m[1])
    if (host !== '') found.add(host.toLowerCase())
  }
  if (found.size === 0) {
    for (const m of command.matchAll(IP_RE)) found.add(m[0])
  }
  return [...found]
}

function isNetworkCommand(command) {
  const text = command.toLowerCase()
  return NETWORK_VERBS.some((verb) => text.includes(verb))
}

function withinTargets(host, targets) {
  return targets.some((t) => {
    const base = String(t).toLowerCase()
    return host === base || host.endsWith(`.${base}`)
  })
}

function readStringArray(value, fallback) {
  if (!Array.isArray(value)) return fallback
  const items = value.filter((v) => typeof v === 'string' && v !== '')
  return items.length > 0 ? items : fallback
}

/**
 * 内核工具是否已挂载——在**调用方 agent 的作用域**里看。
 *
 * 返回 `'yes'` / `'no'` / `'unknown'`。`unknown` 刻意不参与裁决：DSH 是
 * pre-stable，工具服务或 `schemas()` 形状一变就宁可退回原档位——把"API 变了"
 * 误判成"内核没了"，会把一个健康会话整片拒掉，比漏拦更糟。
 *
 * 为什么以"工具列表里有没有 `mcp__proteus__*`"为判据：`failOnStartupError:
 * false` 时内核起不来，preset 照常挂载、只是**没有那组工具**，没有别的信号
 * 能区分"内核在但没用"与"内核根本没起来"。
 *
 * @param {object} ctx - 插件上下文（工具服务可能未注入，访问会抛，故全部兜住）。
 * @param {object} agent - 调用方 agent（`exec.agent`），作为作用域键。
 * @param {string} prefix - 内核工具前缀。
 * @returns {'yes'|'no'|'unknown'} 可用性。
 */
function kernelAvailability(ctx, agent, prefix) {
  let tools
  try {
    tools = ctx?.tools
  } catch {
    tools = undefined
  }
  if (tools === undefined) {
    try {
      tools = ctx?.get?.('tools')
    } catch {
      tools = undefined
    }
  }
  if (tools === undefined || typeof tools.schemas !== 'function') return 'unknown'
  let schemas
  try {
    schemas = tools.schemas(agent)
  } catch {
    return 'unknown'
  }
  if (!Array.isArray(schemas) || schemas.length === 0) return 'unknown'
  return schemas.some((s) => String(s?.name ?? '').startsWith(prefix))
    ? 'yes'
    : 'no'
}

/**
 * 插件入口：按 `role` 承担两件事（同一实现，两个挂载点）。
 *
 * **为什么必须分两个挂载点（真机实测 2026-09-22）**：DSH 的工具派发是
 * **作用域过滤**的——web 路径里 agent 跑在 preset 作用域内，host 平面
 * （bundle/root）的 `tools/pre-execute` 监听**收不到**该作用域的工具调用。
 * 实测：web 会话里 `pwsh curl 127.0.0.1:3000` 直接执行、无审批；而同一份代码
 * 挂在无 preset 的 headless profile 里能拦。审计（`session/event`）是全局事件，
 * 不受此限——所以现象是"审计有记录、裁决不触发"。
 *
 * 于是：
 *   - `role: audit`  → 只做审计（host 平面 bundle 那行用；session/event 全局可见）；
 *   - `role: policy` → 只做裁决（**preset 内**那一行用；工具事件按作用域派发）；
 *   - `role: both`   → 两者都做（缺省，单挂载场景用）。
 *
 * @param {import('@deepseek-ai/cordis').Context} ctx - 宿主上下文。
 * @param {{spoolPath?: string, mode?: string, targets?: string[],
 *          shellTools?: string[], role?: string}} [config] - 由行配置传入。
 */
export function apply(ctx, config = {}) {
  const spoolPath = typeof config.spoolPath === 'string' ? config.spoolPath : ''
  const mode = typeof config.mode === 'string' ? config.mode : 'ask'
  const role = typeof config.role === 'string' ? config.role : 'both'
  const targets = readStringArray(config.targets, ['127.0.0.1', 'localhost'])
  const shellTools = readStringArray(config.shellTools, ['pwsh', 'bash'])
  // 内核缺位时的档位：deny（缺省，fail-closed）/ warn（只提示）/ off
  const kernelGuard = typeof config.kernelGuard === 'string'
      && config.kernelGuard !== ''
    ? config.kernelGuard
    : 'deny'
  const kernelPrefix = typeof config.kernelToolPrefix === 'string'
      && config.kernelToolPrefix !== ''
    ? config.kernelToolPrefix
    : KERNEL_TOOL_PREFIX
  const wantAudit = role === 'both' || role === 'audit'
  const wantPolicy = role === 'both' || role === 'policy'
  if (spoolPath === '') {
    console.warn('[proteus-bridge] 未配置 spoolPath：审计桥未启用')
    return
  }
  try {
    mkdirSync(dirname(spoolPath), { recursive: true })
  } catch (error) {
    console.warn(`[proteus-bridge] spool 目录不可建：${String(error)}`)
  }

  let dropped = 0
  const write = (record) => {
    try {
      appendFileSync(spoolPath, `${JSON.stringify(record)}\n`, 'utf8')
    } catch (error) {
      // fail-open：审计通道写不进去，也不让会话失败
      dropped += 1
      if (dropped === 1 || dropped % 50 === 0) {
        console.warn(`[proteus-bridge] spool 写入失败（已丢 ${dropped} 条）：${String(error)}`)
      }
    }
  }

  // ---- 审计：每次工具调用/结果都留痕（含宿主工具） ----
  if (wantAudit) {
    ctx.on('session/event', (session, event) => {
      const type = event?.type
      if (type !== 'tool/call' && type !== 'tool/result') return
      const data = event?.data ?? {}
      const base = {
        ts: typeof event?.time === 'number' ? event.time : Date.now(),
        session: session?.header?.id ?? '',
        kind: type === 'tool/call' ? 'call' : 'result',
        turn: data.turn,
        step: data.step,
        callId: type === 'tool/call'
          ? (data.callId === undefined ? '' : String(data.callId))
          : resultCallId(data),
      }
      if (type === 'tool/call') {
        write({ ...base, tool: String(data.name ?? ''),
                args: clip(data.arguments, 2000) })
        return
      }
      write({
        ...base,
        isError: resultIsError(data),
        error: data?.error ? clip(data.error, 500) : '',
        output: resultText(data?.message),
      })
    })
  }

  // ---- 裁决：对目标发请求的宿主 shell 命令按档位处理 ----
  // `role: policy` 必须挂在 **preset 作用域**（工具事件按作用域派发，见文件头注释）
  if (!wantPolicy || mode === 'off') return

  ctx.on('tools/pre-execute', async (exec, next) => {
    const name = String(exec?.name ?? '')
    if (!shellTools.includes(name)) return next()
    const command = String(
      exec?.arguments?.command ?? exec?.arguments?.script ?? '')
    if (command === '' || !isNetworkCommand(command)) return next()

    const hosts = targetsIn(command)
    const outside = hosts.filter((host) => !withinTargets(host, targets))
    const kernel = kernelAvailability(ctx, exec?.agent, kernelPrefix)

    // 留痕统一走这里：裁决结果与"当时内核在不在"一起落盘——审计链要能回答
    // "这次动作有没有内核校验"，而不是让人事后猜。
    const record = (decision, reason, extra = {}) => write({
      ts: Date.now(),
      kind: 'policy',
      tool: name,
      decision,
      hosts,
      outside,
      reason: clip(reason, 500),
      command: clip(command, 300),
      kernel,
      ...extra,
    })

    // 内核缺位 + deny 档：目标动作按 fail-closed 拒绝。此时会话没有模式闸门、
    // 目标白名单与证据链，"能用"的代价是把保护整片放弃——宁可拒绝并给出修复路径。
    if (kernel === 'no' && kernelGuard === 'deny') {
      const reason = `目标动作已按 fail-closed 拒绝：内核工具未挂载（工具列表里`
        + `没有任何 ${kernelPrefix}* 工具）。先修内核 MCP 行再重试——`
        + '排查：python tools/dsh_install.py --check，'
        + '见 docs/DSH宿主接入指南.md 第七节。'
        + '本地操作（读写文件、跑本地脚本）不受影响。'
      record('deny', reason, { kernel: 'missing' })
      return { kind: 'deny', reason }
    }

    const base = outside.length > 0
      ? `目标 ${outside.join(', ')} 不在内核授权白名单（${targets.join(', ')}）内；`
        + '内核闸门不会放行这类目标，若确需访问请先显式授权。'
      : '目标动作建议走内核工具（mcp__proteus__http_raw / '
        + 'mcp__proteus__pentest_run 等）：内核侧有目标白名单、模式闸门与'
        + '证据链，宿主 shell 直连的结论不可机验。'
    // warn 档：按原档位走，但把降级状态写进理由——不静默
    const reason = kernel === 'no' && kernelGuard === 'warn'
      ? base + '【注意】内核工具未挂载，本次动作没有内核校验与证据链。'
      : base
    const decision = mode === 'deny'
      ? { kind: 'deny', reason }
      : { kind: 'ask', reason }
    record(decision.kind, reason, kernel === 'no' ? { kernel: 'missing' } : {})
    return decision
  })
}
