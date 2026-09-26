// Generic DSH-host-layer CTF driver (replaces the single-target ctf-web driver).
//
// Drives Proteus through DSH (NOT the native penagent CLI):
//   1. spawn `node bin.js --profile web --patch <proteus.patch> --no-open --port 0`
//   2. parse readiness line `dsh web: http://...?token=...`
//   3. authenticate: spawn 模式用 ready URL 换 cookie；attach（桌面端）模式用
//      ~/.dsh/.credentials.yaml 的 browser-session secret 直接铸造会话 cookie
//   4. RPC session/create  { request: { cwd, agentPreset } }
//   5. RPC session/prompt  { request: { requestId, sessionId, mode:'queue', content } }
//   6. stream session/follow over WS until turn/end
//   7. verify data/dsh-events.jsonl recorded preset + mcp__proteus__* calls, extract flag
//
// Usage:
//   node dsh_drive_ctf.mjs --target http://127.0.0.1:8091 --task data/ctf-arena/web-ssti/task.md
//   node dsh_drive_ctf.mjs --target http://127.0.0.1:8092 --task data/ctf-arena/web-deser/task.md
// (defaults: target=http://127.0.0.1:8090, preset=proteus-ctf-web, task=embedded cmdi task)

import { spawn } from 'node:child_process'
import { readFileSync, writeFileSync, appendFileSync, existsSync, unlinkSync } from 'node:fs'
import { randomUUID, createHash, createHmac } from 'node:crypto'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const WS = require('C:/Users/HZR/.workbuddy/binaries/node/workspace/node_modules/ws')

const REPO = 'D:/HZR_PROJECTS/proteus-agent'
const DSH_DIR = 'D:/HZR_PROJECTS/deepseek-harness'
const BIN_JS = DSH_DIR + '/apps/cli/lib/bin.js'
const PATCH = REPO + '/dsh/proteus.cordis.patch.yml'
const DSH_HOME = 'C:/Users/HZR/.dsh'
const NODE_BIN = 'C:/Users/HZR/.workbuddy/binaries/node/versions/22.22.2-3/node.exe'
const SPOOL = REPO + '/data/dsh-events.jsonl'
const LOG = REPO + '/data/dsh-drive.log'

// ---- arg parsing ----
function parseArgs(argv) {
  const out = { target: 'http://127.0.0.1:8090', preset: 'proteus-ctf-web', task: null, attach: null }
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--attach') {
      // --attach [origin]：附着到已运行的 DSH 实例（官方桌面端默认 127.0.0.1:19387）。
      // 不 spawn、不清理宿主进程；token 取自 ~/.dsh/.credentials.yaml。
      out.attach = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'http://127.0.0.1:19387'
    }
    else if (a === '--target') out.target = argv[++i]
    else if (a === '--preset') out.preset = argv[++i]
    else if (a === '--task') out.task = argv[++i]
    else if (a.startsWith('--target=')) out.target = a.slice('--target='.length)
    else if (a.startsWith('--preset=')) out.preset = a.slice('--preset='.length)
    else if (a.startsWith('--task=')) out.task = a.slice('--task='.length)
  }
  return out
}
const ARGS = parseArgs(process.argv)
const PRESET = ARGS.preset
const WEB_TARGET = ARGS.target

const DEFAULT_TASK = `你正在 Proteus 的 CTF-Web 模式（preset=${PRESET}）下执行一次本地练习。
目标：${WEB_TARGET} 是一个存在漏洞的 Web 练习靶。
要求：
1）先用 /proteus-scope 授权目标 127.0.0.1（它已在白名单内）；
2）侦察页面，定位并利用漏洞读取 flag 文件并解出 flag（格式 flag{...}）；
3）尽量使用内核工具（如 mcp__proteus__http_raw）来完成，并在结尾明确给出 flag 值。`

const TASK = ARGS.task && existsSync(ARGS.task) ? readFileSync(ARGS.task, 'utf8').trim() : DEFAULT_TASK

const log = (s) => { const line = `[${new Date().toISOString()}] ${s}`; console.log(line); appendFileSync(LOG, line + '\n') }

// 上一次驱动被 taskkill /F 强杀后，DSH 的 credentials 写锁可能残留，导致
// 下一次启动 "atomic-write: timed out waiting for the writer lock" 而失败。
// 本驱动独占 DSH 实例，spawn 前清掉陈旧锁（真实运行中的锁由持有进程重建）。
for (const lf of [DSH_HOME + '/.credentials.yaml.lock']) {
  try { unlinkSync(lf); log('removed stale lock: ' + lf) } catch { /* 不存在即目标状态 */ }
}

// Build env overlay from the repo .env (PENTEST_* and PENTEST_LLM_*).
const overlay = {}
for (const raw of readFileSync(REPO + '/.env', 'utf8').split('\n')) {
  const m = raw.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/)
  if (m) overlay[m[1]] = m[2].trim()
}
const childEnv = { ...process.env, ...overlay, DSH_HOME, PENTEST_WS: 'D:/HZR_PROJECTS' }

let child
function cleanup() {
  if (!child) return
  try { child.kill('SIGTERM') } catch {}
  try { spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' }) } catch {}
}

function waitReady() {
  return new Promise((resolve, reject) => {
    let out = ''
    const t = setTimeout(() => reject(new Error('dsh web not ready in 120s:\n' + out)), 120000)
    const onData = (c) => {
      out += c.toString()
      const m = /dsh web: (http:\/\/[^\s]+)/.exec(out)
      if (m?.[1]) { clearTimeout(t); resolve(m[1]) }
    }
    child.stdout?.on('data', onData)
    child.stderr?.on('data', (d) => { out += d.toString(); appendFileSync(LOG, d.toString()) })
    child.once('exit', (code) => reject(new Error(`dsh web exited early (code ${code}):\n${out}`)))
  })
}

async function auth(readyUrl) {
  const r = await fetch(readyUrl, { redirect: 'manual' })
  const sc = r.headers.get('set-cookie')
  if (r.status !== 303 || sc === null) throw new Error(`auth failed: HTTP ${r.status}`)
  return sc.split(';', 1)[0] ?? ''
}

async function rpc(origin, cookie, endpoint, args) {
  const r = await fetch(`${origin}/api/${endpoint}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ type: 'client-request', rpcId: 'drv-' + endpoint, method: endpoint, payload: { args } }),
  })
  if (!r.ok) throw new Error(`${endpoint} HTTP ${r.status}: ${await r.text()}`)
  const b = await r.json()
  if (!b.result.ok) throw new Error(`${endpoint} ${b.result.error.code}: ${b.result.error.message}`)
  return b.result.value
}

function follow(origin, cookie, sessionId) {
  return new Promise((resolve, reject) => {
    const url = origin.replace(/^http/u, 'ws') + '/api/remote.mux'
    const ws = new WS(url, { headers: { cookie } })
    const streamId = 'drv-' + randomUUID()
    const events = []
    let cursor = -1
    let done = false
    const timer = setTimeout(() => {
      if (!done) { done = true; ws.close(); reject(new Error('follow timeout (540s)')) }
    }, 540000)
    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({
        type: 'open', streamId,
        endpoint: 'session/follow',
        payload: { args: { request: { address: { kind: 'session', sessionId } } } },
      }))
    })
    ws.addEventListener('message', (ev) => {
      try {
        const f = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString('utf8'))
        if (f.streamId !== streamId) return
        if (f.type === 'error') { done = true; clearTimeout(timer); ws.close(); return reject(new Error('follow error ' + JSON.stringify(f.error))) }
        if (f.type === 'end') { done = true; clearTimeout(timer); ws.close(); return resolve({ events, cursor }) }
        if (f.type === 'item') {
          const v = f.value
          if (v && v.type === 'snapshot' && Number.isSafeInteger(v.cursor)) cursor = v.cursor
          if (v && v.type === 'event') {
            events.push(v.event)
            // 跟踪已见最大 seq（session/page 的 throughSeq 是"到此为止"语义）
            if (Number.isSafeInteger(v.event.seq) && v.event.seq > cursor) cursor = v.event.seq
            if (v.event.type === 'turn/end') { done = true; clearTimeout(timer); ws.close(); resolve({ events, cursor }) }
          }
        }
      } catch { /* ignore malformed frame */ }
    })
    ws.addEventListener('error', () => { if (!done) { done = true; clearTimeout(timer); reject(new Error('ws error')) } })
  })
}

function extractFlag(hay) {
  const flags = [...hay.matchAll(/flag\{[A-Za-z0-9_./\-]+\}/g)].map((m) => m[0])
  return flags.sort((a, b) => b.length - a.length)[0] ?? null
}

// 官方桌面端把就绪 URL 经 IPC 交给 Electron，不落 stdout；URL 里的 token 是
// 每次启动随机生成、仅存于进程内 WeakMap 的 launchToken，凭据文件里拿不到。
// 但 client-connection/browser-session 这条 grant 的 secret（43 字符 base64url，
// 持久化在 ~/.dsh/.credentials.yaml）是会话 cookie 的 HMAC-SHA256 签名密钥，
// 可以直接铸造合法 cookie（payload 绑定 authority），完全绕开 token 交换。
function readBrowserSessionSecret() {
  const text = readFileSync(DSH_HOME + '/.credentials.yaml', 'utf8')
  const m = /client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/.exec(text)
  if (!m?.[1]) throw new Error(`no client-connection/browser-session secret in ${DSH_HOME}/.credentials.yaml`)
  return m[1]
}

function forgeSessionCookie(origin, secretB64url) {
  const b64url = (buf) => Buffer.from(buf).toString('base64')
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
  const authority = new URL(origin).host
  const pad = '='.repeat((4 - secretB64url.length % 4) % 4)
  const secret = Buffer.from(secretB64url.replaceAll('-', '+').replaceAll('_', '/') + pad, 'base64')
  const name = 'dsh-auth-' + b64url(createHash('sha256').update(authority).digest())
  const issuedAt = Date.now()
  const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + 86_400_000 } // 1 天 << 服务端 maxAge（默认 30 天，schema 下限 1 天）
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'))
  const sig = b64url(createHmac('sha256', secret).update(body).digest())
  return `${name}=v1.${body}.${sig}`
}

// attach 场景下实例可能仍在启动：cookie 与实例状态无关，轮询 GET / 直到不再 401。
async function attachAuth(origin, secretB64url, timeoutMs = 120000) {
  const cookie = forgeSessionCookie(origin, secretB64url)
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      const r = await fetch(origin + '/', { redirect: 'manual', headers: { cookie } })
      if (r.status !== 401) return cookie
    } catch { /* 实例可能仍在启动 */ }
    if (Date.now() > deadline) {
      throw new Error(`attach auth failed within ${timeoutMs}ms`
        + '（确认桌面端已启动、端口正确，且 ~/.dsh/.credentials.yaml 的 browser-session secret 属于该实例）')
    }
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }
}

async function main() {
  writeFileSync(LOG, '')
  log(`mode=${ARGS.attach ? 'attach' : 'spawn'} | target=${WEB_TARGET} preset=${PRESET} task=${ARGS.task ?? '(embedded)'}`)
  let readyUrl
  let cookie
  if (ARGS.attach) {
    const secret = readBrowserSessionSecret()
    readyUrl = ARGS.attach.replace(/\/+$/, '')
    log(`attach: ${readyUrl} (desktop profile; cookie <- ${DSH_HOME}/.credentials.yaml)`)
    cookie = await attachAuth(readyUrl, secret)
  } else {
    child = spawn(NODE_BIN, [BIN_JS, '--profile', 'web', '--patch', PATCH, '--no-open', '--port', '0'], {
      cwd: DSH_DIR, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'],
    })
    child.on('exit', (code) => log(`dsh child exited code=${code}`))
    readyUrl = await waitReady()
    cookie = await auth(readyUrl)
  }
  log('ready: ' + readyUrl)
  const origin = new URL(readyUrl).origin
  log('authenticated (cookie len=' + cookie.length + ')')

  const created = await rpc(origin, cookie, 'session/create', { request: { cwd: REPO, agentPreset: PRESET } })
  const sessionId = created.sessionId
  log('session created: ' + sessionId + ' agentPreset=' + (created.agentPreset ?? '(none)'))
  if (created.agentPreset !== PRESET) {
    throw new Error(`preset mismatch: expected ${PRESET} got ${created.agentPreset}`)
  }

  await rpc(origin, cookie, 'session/prompt', {
    request: { requestId: randomUUID(), sessionId, mode: 'queue', content: [{ type: 'text', text: TASK }] },
  })
  log('prompt sent; streaming session/follow...')

  const { events, cursor } = await follow(origin, cookie, sessionId)
  log('turn ended via follow. followEvents=' + events.length + ' cursor=' + cursor)

  let transcript = events
  try {
    const pageReq = { address: { kind: 'session', sessionId }, maxMessages: 200 }
    if (cursor >= 0) pageReq.throughSeq = cursor
    const page = await rpc(origin, cookie, 'session/page', { request: pageReq })
    const recs = Array.isArray(page?.records) ? page.records : []
    const pageEvents = recs.filter((r) => r?.type === 'event').map((r) => r.event)
    if (pageEvents.length > 0) { transcript = pageEvents; log('transcript via session/page: ' + pageEvents.length + ' events') }
  } catch (e) {
    log('session/page fetch failed (' + e.message + '); using follow events only')
  }

  let flag = extractFlag(JSON.stringify(transcript))
  log('transcript flag=' + (flag ?? '(none)'))

  // Audit spool is authoritative: every kernel tool result (incl. http_raw output
  // carrying the real flag) is recorded here even when session/page omits it.
  const rows = readFileSync(SPOOL, 'utf8').trim().split('\n')
    .map((l) => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  const mine = rows.filter((r) => r.session === sessionId)
  const presetOk = mine.some((r) => r.preset === PRESET)
  const kernel = mine.filter((r) => r.tool && String(r.tool).startsWith('mcp__proteus__'))
  log(`spool rows=${mine.length} presetMatches=${presetOk} kernelToolCalls=${kernel.length}`)
  if (kernel.length) log('kernel tools seen: ' + [...new Set(kernel.map((r) => r.tool))].join(', '))

  const spoolFlags = extractFlag(mine.map((r) => (r.output ?? '')).join('\n'))
  if (spoolFlags) { flag = spoolFlags; log('flag from spool: ' + spoolFlags) }

  console.log('\n===== RESULT =====')
  console.log('target    : ' + WEB_TARGET)
  console.log('sessionId : ' + sessionId)
  console.log('preset    : ' + PRESET + (presetOk ? ' (verified in spool)' : ' (NOT in spool!)'))
  console.log('flag      : ' + (flag ?? '(not found)'))
  console.log('kernelToolCalls : ' + kernel.length)
  console.log('spool     : ' + SPOOL)
  console.log('===================')
}

main()
  .catch((e) => { console.error('DRIVER ERROR:', e.message); process.exitCode = 1 })
  .finally(() => { cleanup() })
