// opencode-go 网关会话头注入代理（桌面端适配专用）。
//
// 背景：opencode.ai Zen 网关对 /go/v1/* 强制要求 x-opencode-session 头
// （缺失 -> 400 MissingSessionID；任意非空值即可 200，见 2026-09-26 实测）。
// 安装版 DSH 桌面端的 llm-pi-ai adapter 不发送该头。
// 本代理监听 127.0.0.1:19388，把请求原样转发到 https://opencode.ai/zen/go/v1，
// 途中注入 x-opencode-session（会话亲和键，固定值即可；不同 DSH 会话共用一个
// 网关侧会话桶不影响正确性，仅影响网关侧路由统计）。
//
// 用法：node opencode_session_proxy.mjs  [port=19388]
// 支持 SSE 流式转发（管道透传，不缓冲）。
import http from 'node:http'
import https from 'node:https'

const PORT = Number(process.argv[2] ?? 19388)
const UPSTREAM_HOST = 'opencode.ai'
const UPSTREAM_PATH_PREFIX = '/zen/go/v1'
const SESSION_HEADER = 'x-opencode-session'
const SESSION_VALUE = 'dsh-desktop-' + 'a46e3d51d459' // 固定亲和键（12 位随机后缀）

const server = http.createServer((req, res) => {
  const chunks = []
  req.on('data', (c) => chunks.push(c))
  req.on('end', () => {
    const body = Buffer.concat(chunks)
    const headers = { ...req.headers }
    delete headers.host
    delete headers.connection
    headers[SESSION_HEADER] = SESSION_VALUE
    const upstream = https.request({
      host: UPSTREAM_HOST,
      port: 443,
      path: UPSTREAM_PATH_PREFIX + req.url,
      method: req.method,
      headers,
    }, (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers)
      up.pipe(res)
    })
    upstream.on('error', (error) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ type: 'error', error: { type: 'proxy', message: String(error) } }))
      } else {
        res.end()
      }
    })
    if (body.length > 0) upstream.write(body)
    upstream.end()
  })
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[opencode-session-proxy] listening http://127.0.0.1:${PORT} -> https://${UPSTREAM_HOST}${UPSTREAM_PATH_PREFIX} (+${SESSION_HEADER})`)
})
