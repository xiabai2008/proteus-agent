/**
 * proteus-commands —— DSH 会话里的 Proteus 人机命令（F2/F3，2026-09-23）。
 *
 * 两个命令：
 *   /proteus-mode [<id>]      查看/设置内核会话默认模式。
 *                             写 data/session-mode.json——内核在 pentest_run
 *                             未显式传 mode 时**逐次读取**该文件，无需重启内核。
 *   /proteus-evidence [<id>]  证据链校验 + 作战记录汇总（spawn 内核 CLI
 *                             `python -m penagent evidence`，与 MCP 工具
 *                             pentest_evidence 共用一份实现）。
 *
 * 设计边界（与接入指南第九节的耦合预算一致）：
 *   - 只注册命令，不做任何裁决、不碰 DSH 内部服务；机制与审计仍在
 *     proteus-tools-policy.mjs，本文件是"人机接口"性质。
 *   - 模式合法性以仓库 modes/*.yaml 文件名为准（单一事实来源）；
 *     写坏时内核侧 fail-open 回落默认模式（见 penagent/mcp.py）。
 *   - 环境变量 PENTEST_WS / PENTEST_PY312 由操作员 setx 持久化
 *     （公开仓库零本机路径约定）。
 */
import { execFile } from 'node:child_process'
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

/** Cordis 诊断用的插件名。 */
export const name = 'proteus-commands'

/** 只依赖 commands 服务（注册面），零额外权限。 */
export const inject = ['commands']

const MODE_HINT = 'pentest-standard / ctf-web / ctf-crypto'

/** 仓库根（PENTEST_WS/proteus-agent）；未配置时返回空串。 */
function repoRoot() {
  const ws = process.env.PENTEST_WS || ''
  return ws ? join(ws, 'proteus-agent') : ''
}

/** 可用模式 id：modes/*.yaml 的文件名（排除 base）。 */
function listModes(root) {
  try {
    return readdirSync(join(root, 'modes'))
      .filter((f) => f.endsWith('.yaml') && f !== 'base.yaml')
      .map((f) => f.slice(0, -'.yaml'.length))
      .sort()
  } catch {
    return []
  }
}

/** 读会话模式（与内核 _read_session_mode 同口径：缺失/损坏 → 空串）。 */
function readSessionMode(statePath) {
  try {
    const data = JSON.parse(readFileSync(statePath, 'utf8'))
    return String(data.mode || '')
  } catch {
    return ''
  }
}

function handleMode(invocation) {
  const root = repoRoot()
  if (!root) {
    return { kind: 'error', text: 'PENTEST_WS 未设置，定位不到 Proteus 仓库根。' }
  }
  const statePath = join(root, 'data', 'session-mode.json')
  const input = String(invocation.rawInput || '').trim()
  const modes = listModes(root)

  if (!input) {
    const current = readSessionMode(statePath)
    return { kind: 'success', text:
      `当前会话模式: ${current || '(未设置，内核按启动参数)'}\n` +
      `可用模式: ${modes.length ? modes.join(', ') : '(modes 目录不可读)'}` }
  }
  if (!modes.includes(input)) {
    return { kind: 'error', text:
      `模式不存在: ${input}（可用: ${modes.join(', ') || MODE_HINT}）` }
  }
  mkdirSync(dirname(statePath), { recursive: true })
  writeFileSync(statePath, JSON.stringify(
    { mode: input, set_at: new Date().toISOString() }, null, 1), 'utf8')
  return { kind: 'success', text:
    `会话模式已设为 ${input}——内核下一次任务生效（无需重启）。` }
}

/** 短命进程调用内核 CLI（超时 20s，错误经 stderr 原文回传）。 */
function runKernelCli(exe, args, cwd) {
  return new Promise((resolve, reject) => {
    execFile(exe, args,
      { cwd, timeout: 20000, windowsHide: true, maxBuffer: 1 << 20 },
      (err, stdout, stderr) => {
        if (err) reject(new Error(String(stderr || err.message).slice(0, 300)))
        else resolve(String(stdout))
      })
  })
}

async function handleEvidence(invocation) {
  const root = repoRoot()
  const py = process.env.PENTEST_PY312 || ''
  if (!root) {
    return { kind: 'error', text: 'PENTEST_WS 未设置，定位不到 Proteus 仓库根。' }
  }
  if (!py) {
    return { kind: 'error', text: 'PENTEST_PY312 未设置（内核解释器目录）。' }
  }
  const mission = String(invocation.rawInput || '').trim()
  const args = ['-m', 'penagent', 'evidence']
  if (mission) args.push('--mission', mission)
  try {
    const out = (await runKernelCli(`${py}/python.exe`, args, root)).trim()
    return { kind: 'success', text: out.slice(0, 4000) || '(空输出)' }
  } catch (e) {
    return { kind: 'error', text: `内核命令执行失败: ${String(e.message || e)}` }
  }
}

/** F4：触发技能导出（内核 CLI 单一实现），产出进 DSH 技能发现目录。 */
async function handleSkills(invocation) {
  const root = repoRoot()
  const py = process.env.PENTEST_PY312 || ''
  if (!root) {
    return { kind: 'error', text: 'PENTEST_WS 未设置，定位不到 Proteus 仓库根。' }
  }
  if (!py) {
    return { kind: 'error', text: 'PENTEST_PY312 未设置（内核解释器目录）。' }
  }
  const namespace = String(invocation.rawInput || '').trim()
  const args = ['-m', 'penagent', 'skills', '--export',
                '--out', join(root, 'data', 'dsh-skills')]
  if (namespace) args.push('--export-namespace', namespace)
  try {
    const out = (await runKernelCli(`${py}/python.exe`, args, root)).trim()
    return { kind: 'success', text: out.slice(0, 2000) }
  } catch (e) {
    return { kind: 'error', text: `技能导出失败: ${String(e.message || e)}` }
  }
}

/** F5：审计通道快览（纯 node fs 读，不起进程）。 */
function handleAudit() {
  const root = repoRoot()
  if (!root) {
    return { kind: 'error', text: 'PENTEST_WS 未设置，定位不到 Proteus 仓库根。' }
  }
  const dataDir = join(root, 'data')
  const lines = []

  // 1) 审计 spool：最近 10 条会话工具调用
  const spoolPath = join(dataDir, 'dsh-events.jsonl')
  let spoolCount = 0
  let recent = []
  try {
    const raw = readFileSync(spoolPath, 'utf8').trim()
    if (raw) {
      const all = raw.split('\n')
      spoolCount = all.length
      recent = all.slice(-10).map((line) => {
        try {
          const e = JSON.parse(line)
          const ts = String(e.ts || e.timestamp || '?').slice(0, 19)
          const tool = String(e.tool || '?')
          const ok = e.ok === undefined ? '?' : String(e.ok)
          const preset = String(e.preset || '?')
          return `  ${ts} · ${tool} · ok=${ok} · preset=${preset}`
        } catch {
          return `  (无法解析的一行，长度 ${line.length})`
        }
      })
    }
  } catch {
    // spool 不存在：审计桥还没产生事件
  }
  lines.push(`审计 spool（dsh-events.jsonl）: ${spoolCount} 条事件`)
  if (recent.length) lines.push(...recent)

  // 2) dsh-sync 状态：增量偏移与链长
  try {
    const state = JSON.parse(readFileSync(join(dataDir, 'dsh-spool.state.json'), 'utf8'))
    lines.push(`dsh-sync 状态: offset=${JSON.stringify(state.offset ?? state)}`
      + (state.updated_at ? ` · 更新于 ${state.updated_at}` : ''))
  } catch {
    lines.push('dsh-sync 状态: 尚无导入记录（data/dsh-spool.state.json 不存在）')
  }
  try {
    const chainRaw = readFileSync(join(dataDir, 'dsh-chain.jsonl'), 'utf8').trim()
    const chainCount = chainRaw ? chainRaw.split('\n').length : 0
    lines.push(`宿主会话证据链（dsh-chain.jsonl）: ${chainCount} 条记录`)
  } catch {
    lines.push('宿主会话证据链: 尚未生成')
  }

  return { kind: 'success', text: lines.join('\n').slice(0, 4000) }
}

/** Cordis 应用入口：注册两个命令（definitionId 可省略，注册表不强制）。 */
export function apply(ctx) {
  ctx.commands.register({
    name: 'proteus-mode',
    description: `查看/设置 Proteus 内核会话默认模式（${MODE_HINT}）`,
    input: { hint: '[<mode-id>]' },
    handler: (invocation) => handleMode(invocation)
  })
  ctx.commands.register({
    name: 'proteus-evidence',
    description: '查看证据链校验与作战记录（可选任务 id 看明细）',
    input: { hint: '[<mission-id>]' },
    handler: (invocation) => handleEvidence(invocation)
  })
  ctx.commands.register({
    name: 'proteus-skills',
    description: '导出内核经验库技能为 DSH 技能（可选分区名过滤）',
    input: { hint: '[<namespace>]' },
    handler: (invocation) => handleSkills(invocation)
  })
  ctx.commands.register({
    name: 'proteus-audit',
    description: '审计通道快览：spool 事件 / dsh-sync 状态 / 证据链规模',
    handler: () => handleAudit()
  })
}
