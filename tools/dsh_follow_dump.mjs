// 重放指定会话的全部事件（attach 模式诊断用）
// 用法: node dsh_follow_dump.mjs <sessionId>
import { readFileSync } from 'node:fs'
import { createHash, createHmac, randomUUID } from 'node:crypto'
import { createRequire } from 'node:module'
import { homedir } from 'node:os'
import { join } from 'node:path'

const require = createRequire(import.meta.url)
// 路径运行时推导（硬规则 7）：ws 模块与 DSH home 都从环境/主目录算
const WS = require(process.env.PROTEUS_WS_MODULE
  ?? join(homedir(), '.workbuddy/binaries/node/workspace/node_modules/ws'))

const DSH_HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const ORIGIN = process.env.DSH_ORIGIN ?? 'http://127.0.0.1:19387'
const sessionId = process.argv[2]
if (!sessionId) { console.error('usage: node dsh_follow_dump.mjs <sessionId>'); process.exit(1) }

function forgeCookie(origin) {
  const b64url = (buf) => Buffer.from(buf).toString('base64')
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
  const authority = new URL(origin).host
  const text = readFileSync(DSH_HOME + '/.credentials.yaml', 'utf8')
  const s = /client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/.exec(text)[1]
  const secret = Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - s.length % 4) % 4), 'base64')
  const name = 'dsh-auth-' + b64url(createHash('sha256').update(authority).digest())
  const issuedAt = Date.now()
  const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + 86_400_000 }
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'))
  const sig = b64url(createHmac('sha256', secret).update(body).digest())
  return `${name}=v1.${body}.${sig}`
}

const url = ORIGIN.replace(/^http/u, 'ws') + '/api/remote.mux'
const ws = new WS(url, { headers: { cookie: forgeCookie(ORIGIN) } })
const streamId = 'dump-' + randomUUID()
ws.addEventListener('open', () => {
  ws.send(JSON.stringify({
    type: 'open', streamId,
    endpoint: 'session/follow',
    payload: { args: { request: { address: { kind: 'session', sessionId } } } },
  }))
})
ws.addEventListener('message', (ev) => {
  let f
  try { f = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString('utf8')) } catch { return }
  if (f.streamId !== streamId) return
  if (f.type === 'end') { ws.close(); console.log('--- end ---'); process.exit(0) }
  if (f.type === 'error') { console.log('--- stream error ---'); console.log(JSON.stringify(f.error, null, 2)); process.exit(0) }
  if (f.type === 'item') console.log(JSON.stringify(f.value))
})
ws.addEventListener('error', (e) => { console.log('ws error', e.message); process.exit(1) })
setTimeout(() => { console.log('--- timeout ---'); process.exit(0) }, 15000)
