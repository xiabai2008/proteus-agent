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
 */

import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

/** Cordis 诊断用的插件名。 */
export const name = 'proteus-bridge'

/** 单个字段的截断上限（字符）。 */
const MAX_TEXT = 4000

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

/**
 * 插件入口：订阅 `session/event`，把 tool/call 与 tool/result 追加进 spool。
 *
 * @param {import('@deepseek-ai/cordis').Context} ctx - 宿主上下文。
 * @param {{spoolPath?: string}} [config] - 由 bundle 补丁层传入的配置。
 */
export function apply(ctx, config = {}) {
  const spoolPath = typeof config.spoolPath === 'string' ? config.spoolPath : ''
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
      write({ ...base, tool: String(data.name ?? ''), args: clip(data.arguments, 2000) })
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
