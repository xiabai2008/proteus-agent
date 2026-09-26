// 桌面端 standard preset 冒烟测试：创建无 preset 会话、发一条消息、拉结果。
import { readFileSync } from 'node:fs'
import { createHash, createHmac, randomUUID } from 'node:crypto'

const ORIGIN = 'http://127.0.0.1:19387'
const b64url = (buf) => Buffer.from(buf).toString('base64')
  .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
const authority = new URL(ORIGIN).host
const text = readFileSync('C:/Users/HZR/.dsh/.credentials.yaml', 'utf8')
const s = /client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/.exec(text)[1]
const secret = Buffer.from(s.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - s.length % 4) % 4), 'base64')
const name = 'dsh-auth-' + b64url(createHash('sha256').update(authority).digest())
const issuedAt = Date.now()
const payload = { version: 1, authority, issuedAt, expiresAt: issuedAt + 86_400_000 }
const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'))
const sig = b64url(createHmac('sha256', secret).update(body).digest())
const cookie = `${name}=v1.${body}.${sig}`

const rpc = async (endpoint, args) => {
  const r = await fetch(ORIGIN + '/api/' + endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ type: 'client-request', rpcId: 'smoke-' + endpoint, method: endpoint, payload: { args } }),
  })
  return (await r.json()).result
}

const created = await rpc('session/create', { request: { cwd: 'D:/HZR_PROJECTS/proteus-agent' } })
if (!created.ok) { console.log('create fail', JSON.stringify(created).slice(0, 300)); process.exit(1) }
const sid = created.value.id ?? created.value.sessionId
console.log('standard session:', sid)
const prompted = await rpc('session/prompt', {
  request: { requestId: 'smoke-' + randomUUID(), sessionId: sid, mode: 'queue', content: [{ type: 'text', text: '只回复两个字：收到' }] },
})
console.log('prompt:', JSON.stringify(prompted).slice(0, 400))
for (const wait of [10, 25, 50]) {
  await new Promise((r) => setTimeout(r, wait * 1000))
  const page = await rpc('session/page', { request: { address: { kind: 'session', sessionId: sid }, throughSeq: 0, maxMessages: 100 } })
  const evs = (page.value?.records || []).map((r) => `${r.event?.type}@${r.event?.seq}`)
  console.log(`+${wait}s events:`, evs.join(', ') || '(empty)')
  if (evs.some((e) => e.startsWith('turn/end'))) break
  if (wait === 10) continue
  for (const rec of page.value?.records || []) {
    const ev = rec.event || {}
    if (['assistant/attempt', 'turn/end'].includes(ev.type)) {
      console.log('  seq=' + ev.seq, ev.type, JSON.stringify(ev.data).slice(0, 400))
    }
  }
}
