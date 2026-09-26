// 桌面端 DSH 诊断小工具：铸 cookie + 调任意 RPC endpoint。
// 用法：
//   node dsh_desktop_rpc.mjs agent-presets/list
//   node dsh_desktop_rpc.mjs <endpoint> '<json-args>'
// cookie 铸法见 dsh_drive_ctf.mjs 的 forgeSessionCookie（同一实现）。
import { readFileSync } from 'node:fs'
import { createHash, createHmac } from 'node:crypto'

const DSH_HOME = 'C:/Users/HZR/.dsh'
const ORIGIN = 'http://127.0.0.1:19387'

function readSecret() {
  const text = readFileSync(DSH_HOME + '/.credentials.yaml', 'utf8')
  const m = /client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/.exec(text)
  if (!m?.[1]) throw new Error('no browser-session secret in ' + DSH_HOME + '/.credentials.yaml')
  return m[1]
}

function forgeCookie(origin) {
  const b64url = (buf) => Buffer.from(buf).toString('base64')
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
  const authority = new URL(origin).host
  const s = readSecret()
  const secret = Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - s.length % 4) % 4), 'base64')
  const name = 'dsh-auth-' + b64url(createHash('sha256').update(authority).digest())
  const issuedAt = Date.now()
  const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + 86_400_000 }
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'))
  const sig = b64url(createHmac('sha256', secret).update(body).digest())
  return `${name}=v1.${body}.${sig}`
}

const [endpoint, argsRaw] = process.argv.slice(2)
if (!endpoint) {
  console.error('usage: node dsh_desktop_rpc.mjs <endpoint> [json-args]')
  process.exit(1)
}
let args
try { args = argsRaw ? JSON.parse(argsRaw) : {} } catch {
  console.error('invalid JSON args')
  process.exit(1)
}

const cookie = forgeCookie(ORIGIN)
const r = await fetch(`${ORIGIN}/api/${endpoint}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie },
  body: JSON.stringify({ type: 'client-request', rpcId: 'diag-' + endpoint, method: endpoint, payload: { args } }),
})
console.log('HTTP', r.status)
const text = await r.text()
try { console.log(JSON.stringify(JSON.parse(text), null, 2)) } catch { console.log(text) }
