/* Proteus 控制台前端：模式选择（关键词触发）→ 任务下发（实时步骤流）→ 证据链校验。
   纯原生 JS，无构建步骤；与后端 web/server.py 的 JSON/SSE 接口对接。 */
'use strict'

const state = { modes: [], selected: null, mission: null, stream: null }

const $ = (id) => document.getElementById(id)

async function api(path, options) {
  const response = await fetch(path, options)
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(payload.error || response.statusText)
  return payload
}

// ── 一、模式选择与关键词触发 ─────────────────────────────────────────
function renderModes(hits = {}) {
  const box = $('modes')
  box.innerHTML = ''
  for (const mode of state.modes) {
    const hit = hits[mode.id] || []
    const el = document.createElement('div')
    el.className = 'mode' + (state.selected === mode.id ? ' active' : '') +
      (hit.length ? ' hit' : '')
    el.dataset.mode = mode.id
    el.innerHTML = `
      <div class="row">
        <span class="name">${mode.label}</span>
        <span class="id">${mode.id}</span>
      </div>
      <div class="meta">
        判定器 <span class="tag ${mode.verifier.type === 'flag_regex' ? 'v-flag' : 'v-chain'}">${mode.verifier.type}</span>
        · 预算 ${mode.budget.max_steps} 步 / ${mode.budget.max_minutes ?? '-'} 分钟
        · 沙箱 ${mode.sandbox}
        · 工具 allow ${mode.capability.allow.length} / deny ${mode.capability.deny.length}
      </div>
      <div class="triggers">
        ${mode.triggers.map((t) =>
          `<span class="tag ${hit.includes(t) ? 'hit' : ''}">${t}</span>`).join('')}
      </div>`
    el.onclick = () => { state.selected = mode.id; renderModes(hits) }
    box.appendChild(el)
  }
}

async function probeTriggers() {
  const text = $('probe').value.trim()
  if (!text) return renderModes({})
  try {
    const data = await api('/api/suggest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    })
    const hits = {}
    for (const item of data.suggestions) hits[item.id] = item.hits
    renderModes(hits)
    const top = data.suggestions[0]
    $('dispatch-note').textContent = top
      ? `关键词推荐：${top.label}（命中 ${top.hits.join('、')}）`
      : '关键词未命中任何模式'
  } catch (error) {
    $('dispatch-note').textContent = `推荐失败：${error.message}`
  }
}

// ── 二、任务下发与实时步骤流 ─────────────────────────────────────────
function stepNode(index, step) {
  const el = document.createElement('div')
  const blocked = Boolean(step.blocked)
  const failed = step.ok === false && !blocked
  el.className = 'step' + (blocked ? ' blocked' : failed ? ' fail' : '')
  const detail = blocked
    ? `拦截：${step.reason ?? ''}`
    : JSON.stringify(step.output ?? step.reason ?? '', null, 0)
  el.innerHTML = `
    <div class="head">
      <span class="idx">#${index}</span>
      <span class="tool">${step.tool ?? '-'}</span>
      <span class="muted small">${blocked ? '被护栏拦截' : failed ? '执行失败' : '已完成'}</span>
    </div>
    <pre>${detail.slice(0, 600)}</pre>`
  return el
}

function showVerdict(event) {
  const el = document.createElement('div')
  const ok = event.outcome === 'success'
  el.className = 'verdict ' + (ok ? 'ok' : 'bad')
  const flag = event.flag ? ` <span class="flag">${event.flag}</span>` : ''
  el.innerHTML = `${ok ? '判定通过' : '判定未通过'}｜outcome=${event.outcome}｜步数 ${event.steps}${flag}`
  $('stream').appendChild(el)
  if (event.summary) {
    const note = document.createElement('div')
    note.className = 'muted small'
    note.textContent = event.summary.slice(0, 300)
    $('stream').appendChild(note)
  }
}

function openStream(modeId, missionId) {
  if (state.stream) state.stream.close()
  const url = `/api/stream/${missionId}?mode=${encodeURIComponent(modeId)}`
  const source = new EventSource(url)
  state.stream = source
  source.onmessage = (message) => {
    const event = JSON.parse(message.data)
    if (event.type === 'step') {
      $('stream').appendChild(stepNode(event.index, event.step))
    } else if (event.type === 'verdict') {
      showVerdict(event)
      source.close()
      loadEvidence(modeId, missionId)
    }
  }
  source.onerror = () => source.close()
}

async function dispatch() {
  if (!state.selected) {
    $('dispatch-note').textContent = '请先在上方选择模式'
    return
  }
  $('dispatch').disabled = true
  $('stream').innerHTML = ''
  $('dispatch-note').textContent = '任务已下发，等待内核记录…'
  try {
    const task = await api('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: state.selected,
        target: $('target').value.trim(),
        objective: $('objective').value.trim(),
        driver: $('driver').value,
        challenge: $('challenge').value,
      }),
    })
    state.mission = task.key
    let missionId = ''
    for (let i = 0; i < 60 && !missionId; i++) {
      await new Promise((resolve) => setTimeout(resolve, 500))
      const info = await api(`/api/state/${task.key}`)
      if (info.status === 'error') throw new Error(info.error)
      missionId = info.mission_id
    }
    if (!missionId) throw new Error('内核未返回作战记录 id')
    $('dispatch-note').textContent =
      `模式 ${task.mode}｜驱动 ${task.driver}｜mission ${missionId}`
    openStream(state.selected, missionId)
  } catch (error) {
    $('dispatch-note').textContent = `下发失败：${error.message}`
  } finally {
    $('dispatch').disabled = false
  }
}

// ── 三、证据链校验 ───────────────────────────────────────────────────
async function loadEvidence(modeId, missionId = '') {
  const mode = modeId || state.selected
  if (!mode) return
  const path = missionId
    ? `/api/evidence/${mode}/${missionId}` : `/api/evidence/${mode}`
  const data = await api(path)
  const integrity = data.integrity || {}
  const conclusion = data.conclusion
  const rows = (data.records || []).slice(-12).reverse().map((record) => `
    <tr>
      <td class="mono">${record.seq}</td>
      <td>${record.kind}</td>
      <td class="mono">${(record.hash || '').slice(0, 12)}…</td>
      <td class="mono">${(record.prev_hash || '').slice(0, 12)}…</td>
    </tr>`).join('')
  $('evidence').innerHTML = `
    <p>链完整性：
      <span class="badge ${integrity.ok ? 'ok' : 'bad'}">
        ${integrity.ok ? '通过' : '被篡改'}
      </span>
      <span class="muted small">共 ${data.total} 条记录（${data.chain_file}）</span>
    </p>
    ${conclusion ? `
      <p class="small">收口结论：<span class="muted">${
        (conclusion.content && conclusion.content.verdict) || '-'}</span><br>
        证据引用：<span class="mono">${
        JSON.stringify(conclusion.content && conclusion.content.evidence_refs)}</span></p>`
      : '<p class="muted small">尚无收口结论</p>'}
    <div class="scroll"><table>
      <thead><tr><th>seq</th><th>类型</th><th>hash</th><th>prev</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`
}

// ── 启动 ─────────────────────────────────────────────────────────────
async function boot() {
  const data = await api('/api/modes')
  state.modes = data.modes
  state.selected = data.modes.find((m) => m.id === 'ctf-web')?.id
    || data.modes[0]?.id
  renderModes({})
  $('probe').addEventListener('input', () => {
    clearTimeout(boot.timer)
    boot.timer = setTimeout(probeTriggers, 250)
  })
  $('dispatch').onclick = dispatch
  $('refresh-evidence').onclick = () => loadEvidence()
  loadEvidence()
}

boot().catch((error) => {
  document.body.insertAdjacentHTML('beforeend',
    `<p style="padding:0 24px;color:#cc4b4b">初始化失败：${error.message}</p>`)
})
