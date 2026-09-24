/**
 * proteus-supervisor —— 宿主侧监督层：循环检测与救场（P2-1，2026-09-24 拍板 D3）。
 *
 * 为什么放宿主侧：DSH 会话里的重复调用是**外层 agent 的行为**，内核看不见；
 * 而内核自己的循环有 budget/max_steps 兜底。监督放在 preset 作用域内（与
 * `tools/pre-execute` 的派发规则一致，见 proteus-tools-policy.mjs 文件头）。
 *
 * 判据（借 PentAGI 的监督层阈值，缺省同工具 5 次 / 会话总量 30 次）：
 * - **同工具 + 同参数**重复到阈值 → `deny` 并把"换思路"的提示写进理由。
 *   实测教训（2026-09-22）：一次会话 20 步里有 13 步在重复同一个
 *   `http_raw /ftp`（页面长、清单被截断，模型就一遍遍加大 max_body）——
 *   这类循环烧掉的是整轮预算，而模型自己往往意识不到。
 * - 再触发一次 → 升级为 `ask`（让人看一眼，而不是无限拒绝）。
 *
 * 边界（诚实声明）：
 * - 只数与拦，**不改工具结果**；不判断"这次调用是否有意义"（那要靠模型）。
 * - 会话 id 取不到时按 `unknown` 计——可能跨会话累计，宁可多拦一次也不漏。
 * - **不按工具名过滤：监督覆盖会话里的全部工具**（含宿主自己的、非内核的）。
 *   刻意如此：一次会话的循环可能发生在任何工具上，只盯内核工具等于给"换个
 *   工具继续绕"留口子。曾有过一个 `toolPrefix` 配置项想做这层过滤，但从未被
 *   任何判据使用——2026-09-24 删掉：**写进配置却不生效比没有更坏**，它会让
 *   读配置的人以为过滤存在（见 docs/修复待办清单.md R-42）。
 * - 留痕进 spool（kind=`supervisor`），审计链能回答"谁在什么时候被拦了"。
 */

/** Cordis 诊断用的插件名。 */
export const name = 'proteus-supervisor'

/** 不注入任何服务：只订阅工具执行前钩子，零额外权限。 */
export const inject = []

import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

function clip(value, limit = 400) {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? '')
  return text.length > limit ? `${text.slice(0, limit)}…` : text
}

/** 调用指纹：工具名 + 规范化参数（键序无关）。 */
function fingerprint(name, args) {
  let body
  try {
    const keys = Object.keys(args || {}).sort()
    body = JSON.stringify(keys.map((k) => [k, args[k]]))
  } catch {
    body = String(args)
  }
  return `${name}::${body}`
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx - 宿主上下文。
 * @param {{spoolPath?: string, sameToolLimit?: number, totalLimit?: number,
 *          escalate?: string}} [config] - 行配置。
 */
export function apply(ctx, config = {}) {
  const spoolPath = typeof config.spoolPath === 'string' ? config.spoolPath : ''
  const sameToolLimit = Number.isFinite(config.sameToolLimit)
    ? Number(config.sameToolLimit) : 5
  const totalLimit = Number.isFinite(config.totalLimit)
    ? Number(config.totalLimit) : 30
  const escalate = typeof config.escalate === 'string' && config.escalate !== ''
    ? config.escalate : 'ask'

  /** 会话 → { repeats: Map<指纹, 次数>, total: 次数, intervened: 次数 } */
  const sessions = new Map()

  const write = (record) => {
    if (spoolPath === '') return
    try {
      mkdirSync(dirname(spoolPath), { recursive: true })
      appendFileSync(spoolPath, `${JSON.stringify(record)}\n`, 'utf8')
    } catch {
      /* fail-open：监督通道写不进去，也不让会话失败 */
    }
  }

  const sessionKeyOf = (exec) => {
    const id = exec?.agent?.session?.header?.id
    return typeof id === 'string' && id !== '' ? id : 'unknown'
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    const name = String(exec?.name ?? '')
    const args = exec?.arguments ?? {}
    const key = sessionKeyOf(exec)
    let state = sessions.get(key)
    if (!state) {
      state = { repeats: new Map(), total: 0, intervened: 0 }
      sessions.set(key, state)
    }
    state.total += 1
    const fp = fingerprint(name, args)
    const seen = (state.repeats.get(fp) || 0) + 1
    state.repeats.set(fp, seen)

    if (seen < sameToolLimit && state.total <= totalLimit) return next()

    state.intervened += 1
    const repeated = seen >= sameToolLimit
    const detail = repeated
      ? `同一个调用（${name}）已重复 ${seen} 次`
      : `本会话工具调用已达 ${state.total} 次`
    const reason = `${detail}——监督层判定为陷入循环。`
      + '换思路：改写参数（例如长页面改用 grep 做定向提取，不要加大 max_body）、'
      + '换一个工具验证同一个假设，或停下来把卡点如实告诉人。'
      + '（内核侧工具另有步数预算，本条只拦宿主会话里的循环。）'
    const decision = (state.intervened >= 2 && escalate === 'ask')
      ? 'ask' : 'deny'
    write({
      ts: Date.now(),
      kind: 'supervisor',
      tool: name,
      session: key,
      decision,
      repeats: seen,
      total: state.total,
      args: clip(args),
      reason: clip(reason, 500),
    })
    if (decision === 'deny') return { kind: 'deny', reason }
    return { kind: 'ask', reason }
  })
}
