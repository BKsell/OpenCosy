'use strict'

// mixedcontentguard.js —— HTTPS 页面内的混合内容（mixed content）守卫。
//
// 威胁模型：
//   HTTPS 页面引用 http:// 子资源会破坏传输安全：
//     - 主动混合内容（script/iframe/fetch/websocket/XHR/worker）：可被中间人替换执行；
//     - 被动混合内容（img/audio/video 源）：多数浏览器自动升级，失败再拦截，但仍应显式升级；
//   ws://（非 wss://）从 https 页发起同样是明文主动混合内容；
//   data:/blob: 不属于混合内容（按其自身风险另算）。
//
// 本模块对"页面协议 + 子资源 URL + 资源类型"做判定，给出 block / upgrade / allow 结论。

const MC_KIND = Object.freeze({
  ACTIVE: 'active',
  PASSIVE: 'passive',
  NEUTRAL: 'neutral'
})

const MC_ACTION = Object.freeze({
  BLOCK: 'block',
  UPGRADE: 'upgrade',
  ALLOW: 'allow'
})

const MC_REASON = Object.freeze({
  ACTIVE_MIXED: 'mc-active-mixed-content',
  PASSIVE_MIXED: 'mc-passive-mixed-content',
  INSECURE_WS: 'mc-insecure-websocket'
})

// 资源类型 → 是否主动内容。
const MC_ACTIVE_TYPES = Object.freeze({
  script: true, 'service-worker': true, worker: true, 'shared-worker': true,
  iframe: true, frame: true, fetch: true, xhr: true, ajax: true,
  stylesheet: true, css: true, object: true, embed: true, websocket: true,
  eventsource: true, manifest: true, import: true
})
const MC_PASSIVE_TYPES = Object.freeze({
  image: true, img: true, audio: true, video: true, 'media-source': true,
  font: true, icon: true, favicon: true
})

function defaultMixedContentPolicy () {
  return {
    blockActive: true,
    upgradePassive: true, // 被动内容给出 upgrade 动作而非直接放行
    treatWsAsActive: true
  }
}

function mcScheme (url) {
  const s = String(url || '')
  const idx = s.indexOf(':')
  if (idx <= 0) return ''
  return s.slice(0, idx).toLowerCase()
}

function mcClassifyType (type) {
  const t = String(type || '').toLowerCase()
  if (MC_ACTIVE_TYPES[t]) return MC_KIND.ACTIVE
  if (MC_PASSIVE_TYPES[t]) return MC_KIND.PASSIVE
  return MC_KIND.NEUTRAL
}

class MixedContentGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultMixedContentPolicy(), policy || {})
  }

  // context: { pageScheme:'https' }；request: { url, type }
  evaluate (request, context) {
    const pol = this.policy
    const ctx = context || {}
    const pageSecure = (ctx.pageScheme || '').toLowerCase() === 'https'
    const url = (request && request.url) || ''
    const scheme = mcScheme(url)
    const kind = mcClassifyType(request && request.type)
    const findings = []

    if (!pageSecure) {
      return { action: MC_ACTION.ALLOW, securePage: false, findings }
    }

    if (scheme === 'ws') {
      findings.push({ reason: MC_REASON.INSECURE_WS, url: url })
      return { action: pol.treatWsAsActive ? MC_ACTION.BLOCK : MC_ACTION.UPGRADE,
        kind: MC_KIND.ACTIVE, findings }
    }
    if (scheme === 'wss' || scheme === 'https' || scheme === 'data' ||
        scheme === 'blob' || scheme === 'file' || scheme === '') {
      return { action: MC_ACTION.ALLOW, securePage: true, kind: kind, findings }
    }
    if (scheme !== 'http') {
      return { action: MC_ACTION.ALLOW, securePage: true, kind: kind, findings }
    }

    // scheme === 'http'
    if (kind === MC_KIND.ACTIVE) {
      findings.push({ reason: MC_REASON.ACTIVE_MIXED, url: url, type: request.type })
      return { action: pol.blockActive ? MC_ACTION.BLOCK : MC_ACTION.UPGRADE, kind: kind, findings }
    }
    if (kind === MC_KIND.PASSIVE) {
      findings.push({ reason: MC_REASON.PASSIVE_MIXED, url: url, type: request.type })
      return { action: pol.upgradePassive ? MC_ACTION.UPGRADE : MC_ACTION.ALLOW, kind: kind, findings }
    }
    // 未声明类型的 http 资源按主动内容保守处理。
    findings.push({ reason: MC_REASON.ACTIVE_MIXED, url: url, type: 'unknown' })
    return { action: pol.blockActive ? MC_ACTION.BLOCK : MC_ACTION.UPGRADE, kind: MC_KIND.NEUTRAL, findings }
  }
}

module.exports = Object.freeze({
  MC_KIND: MC_KIND,
  MC_ACTION: MC_ACTION,
  MC_REASON: MC_REASON,
  defaultMixedContentPolicy: defaultMixedContentPolicy,
  mcScheme: mcScheme,
  mcClassifyType: mcClassifyType,
  MixedContentGuard: MixedContentGuard
})
