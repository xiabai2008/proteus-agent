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
}
