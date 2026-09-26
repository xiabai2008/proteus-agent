// Drive Proteus through the DSH host layer (NOT the native penagent CLI).
//
// Recipe (mirrors apps/web/tests/smoke-real.e2e.ts):
//   1. spawn `node bin.js --profile web --patch <proteus.patch> --no-open --port 0`
//   2. parse readiness line `dsh web: http://...?token=...`
//   3. exchange token for a session cookie (303 + set-cookie)
//   4. RPC session/create  { request: { cwd, agentPreset: 'proteus-ctf-web' } }
//   5. RPC session/prompt  { request: { requestId, sessionId, mode:'queue', content } }
//   6. stream session/follow over WS until turn/end; collect events
//   7. verify data/dsh-events.jsonl recorded preset=proteus-ctf-web + mcp__proteus__* calls
//
// The kernel MCP server is spawned by DSH with cwd=<PENTEST_WS>/proteus-agent,
// so --data data resolves to <repo>/data. PENTEST_* + PENTEST_LLM_* are forwarded
// from the local .env into the DSH process env (the kernel reads them at spawn).

import { spawn } from 'node:child_process'
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Node's global WebSocket (undici) ignores custom headers, so the auth cookie
// cannot be set on the session/follow upgrade. Use the `ws` package instead
// (exact e2e path), loaded via createRequire.
//
// 路径全部运行时推导（硬规则 7：入库文件不得含本机路径）。
const require = createRequire(import.meta.url)
const REPO = process.env.PENTEST_REPO
  ?? dirname(dirname(fileURLToPath(import.meta.url)))
const WS = require(process.env.PROTEUS_WS_MODULE
  ?? join(homedir(), '.workbuddy/binaries/node/workspace/node_modules/ws'))
const WS_ROOT = process.env.PENTEST_WS ?? dirname(REPO)
const DSH_DIR = process.env.PENTEST_DSH_REPO ?? join(WS_ROOT, 'deepseek-harness')
const BIN_JS = DSH_DIR + '/apps/cli/lib/bin.js'
const PATCH = REPO + '/dsh/proteus.cordis.patch.yml'
const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const NODE_BIN = process.execPath
const PRESET = 'proteus-ctf-web'
const WEB_TARGET = 'http://127.0.0.1:8090'
const SPOOL = REPO + '/data/dsh-events.jsonl'
const LOG = REPO + '/data/dsh-drive.log'

const TASK = `你正在 Proteus 的 CTF-Web 模式（preset=${PRESET}）下执行一次本地练习。
目标：http://127.0.0.1:8090 是一个名为 "NetProbe Lite" 的主机探测页面，存在命令注入漏洞。
要求：
1）先用 /proteus-scope 授权目标 127.0.0.1（它已在白名单内）；
2）侦察页面，定位命令注入点，利用漏洞读取 flag 文件并解出 flag（格式 flag{...}）；
3）尽量使用内核工具（如 mcp__proteus__http_raw）来完成，并在结尾明确给出 flag 值。`

const log = (s) => { const line = `[${new Date().toISOString()}] ${s}`; console.log(line); appendFileSync(LOG, line + '\n') }

// Build env overlay from the repo .env (PENTEST_* and PENTEST_LLM_*).
const overlay = {}
for (const raw of readFileSync(REPO + '/.env', 'utf8').split('\n')) {
  const m = raw.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/)
  if (m) overlay[m[1]] = m[2].trim()
}
const childEnv = { ...process.env, ...overlay, DSH_HOME, PENTEST_WS: WS_ROOT }

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
            if (v.event.type === 'turn/end') { done = true; clearTimeout(timer); ws.close(); resolve({ events, cursor }) }
          }
        }
      } catch { /* ignore malformed frame */ }
    })
    ws.addEventListener('error', () => { if (!done) { done = true; clearTimeout(timer); reject(new Error('ws error')) } })
  })
}

async function fetchTranscript(origin, cookie, sessionId, throughSeq) {
  const page = await rpc(origin, cookie, 'session/page', {
    request: { address: { kind: 'session', sessionId }, throughSeq, maxMessages: 200 },
  })
  const records = Array.isArray(page?.records) ? page.records : []
  const events = records.filter((r) => r?.type === 'event').map((r) => r.event)
  return events
}

async function main() {
  writeFileSync(LOG, '')
  log('launching dsh web profile with preset patch...')
  child = spawn(NODE_BIN, [BIN_JS, '--profile', 'web', '--patch', PATCH, '--no-open', '--port', '0'], {
    cwd: DSH_DIR, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.on('exit', (code) => log(`dsh child exited code=${code}`))

  const readyUrl = await waitReady()
  log('ready: ' + readyUrl)
  const origin = new URL(readyUrl).origin
  const cookie = await auth(readyUrl)
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

  // Pull the full transcript (proven e2e path) for authoritative flag scan.
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

  const hay = JSON.stringify(transcript)
  // Prefer the most complete flag token: a placeholder like "flag{...}" (often
  // in an assistant's format note) is shorter than the real flag.
  const flags = [...hay.matchAll(/flag\{[A-Za-z0-9_./\-]+\}/g)].map((m) => m[0])
  let flag = flags.sort((a, b) => b.length - a.length)[0] ?? null
  log('transcript flag candidates=' + (flags.length ? JSON.stringify(flags) : '(none)') + ' -> ' + (flag ?? '(none)'))

  // Verify audit spool.
  const spoolText = readFileSync(SPOOL, 'utf8')
  const rows = spoolText.trim().split('\n').map((l) => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean)
  const mine = rows.filter((r) => r.session === sessionId)
  const presetOk = mine.some((r) => r.preset === PRESET)
  const kernel = mine.filter((r) => r.tool && String(r.tool).startsWith('mcp__proteus__'))
  log(`spool rows for session=${mine.length}, presetMatches=${presetOk}, kernelToolCalls=${kernel.length}`)
  if (kernel.length) log('kernel tools seen: ' + [...new Set(kernel.map((r) => r.tool))].join(', '))

  // The audit spool records every kernel tool result (including http_raw output
  // that carries the real flag), so it is the authoritative flag source even
  // when the session/page tail omits the earlier tool-result events.
  const spoolHay = mine.map((r) => (r.output ?? '')).join('\n')
  const spoolFlags = [...spoolHay.matchAll(/flag\{[A-Za-z0-9_./\-]+\}/g)].map((m) => m[0])
  if (spoolFlags.length) {
    const best = spoolFlags.sort((a, b) => b.length - a.length)[0]
    if (!flag || (best && best.length > flag.length)) { flag = best; log('flag upgraded from spool: ' + best) }
  }

  console.log('\n===== RESULT =====')
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
