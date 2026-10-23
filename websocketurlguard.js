'use strict'

// websocketurlguard.js —— WebSocket 连接 URL（ws/wss）的来源与明文守卫。
//
// 威胁模型：
//   浏览器内置页面/扩展可能开 WebSocket 做通知、调试。错误做法：
//     - https 页面里连 ws://（明文，会话标识可被中间人窃取/篡改）；
//     - 连到内网/环回/云元数据地址（结合 ipliteralguard）；
//     - 用 page 提供的任意 host 直接 new WebSocket（SSRF/打内网，ws 不受 CORS 保护）；
//     - URL 里把 token 放在 query（会进代理日志）。
//   本模块审计 { url, pageScheme, allowInternal, tokenInQuery }。纯字符判定，不使用正则。

const { ilClassifyV4 } = require('./ipliteralguard.js')

const WU_REASON = Object.freeze({
  BAD_SCHEME: 'websocket-url-scheme-not-ws-or-wss',
  DOWNGRADE: 'secure-page-opens-plaintext-websocket',
  INTERNAL_TARGET: 'websocket-target-host-is-internal-ip',
  TOKEN_IN_QUERY: 'websocket-url-carries-secret-token-in-query',
  EMPTY_HOST: 'websocket-url-has-empty-host'
})

const INTERNAL = new Set(['loopback', 'private', 'linklocal'])

function wuParse (url) {
  const sep = String(url).indexOf('://')
  if (sep < 0) return { scheme: '', rest: '' }
  const scheme = String(url).slice(0, sep).toLowerCase()
  const rest = String(url).slice(sep + 3)
  let host = rest
  const slash = wuIndexAny(host, ['/', '?', '#'])
  if (slash >= 0) host = host.slice(0, slash)
  const at = host.lastIndexOf('@')
  if (at >= 0) host = host.slice(at + 1)
  if (host[0] === '[') {
    const c = host.indexOf(']')
    host = c >= 0 ? host.slice(1, c) : host
  } else {
    const colon = host.indexOf(':')
    if (colon >= 0) host = host.slice(0, colon)
  }
  const query = String(url).indexOf('?') >= 0
  return { scheme: scheme, host: host, hasQuery: query, raw: String(url) }
}

function wuIndexAny (s, chars) {
  for (let i = 0; i < s.length; i++) if (chars.indexOf(s[i]) >= 0) return i
  return -1
}

function wuIsAsciiIp (host) {
  for (let i = 0; i < host.length; i++) {
    const c = host[i]
    if (!((c >= '0' && c <= '9') || c === '.')) return false
  }
  return host.indexOf('.') >= 0
}

class WebSocketUrlGuard {
  // in: { url, pageScheme, allowInternal, secretQueryKeys:['token','access_token'] }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const u = wuParse(inp.url)
    if (u.scheme !== 'ws' && u.scheme !== 'wss') findings.push({ reason: WU_REASON.BAD_SCHEME })
    if (!u.host) findings.push({ reason: WU_REASON.EMPTY_HOST })
    if (inp.pageScheme === 'https' && u.scheme === 'ws') findings.push({ reason: WU_REASON.DOWNGRADE })
    if (!inp.allowInternal && u.host && wuIsAsciiIp(u.host)) {
      if (INTERNAL.has(ilClassifyV4(u.host))) findings.push({ reason: WU_REASON.INTERNAL_TARGET, detail: u.host })
    }
    if (u.hasQuery) {
      const qs = inp.secretQueryKeys || ['token', 'access_token', 'auth', 'key']
      if (wuHasSecretQuery(u.raw, qs)) findings.push({ reason: WU_REASON.TOKEN_IN_QUERY })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

// 参数名必须位于 '?' 或 '&' 之后，避免 not_token= 这类前缀误报。
function wuHasSecretQuery (rawUrl, keys) {
  const lower = rawUrl.toLowerCase()
  for (const k of keys) {
    const needle = k.toLowerCase() + '='
    let from = 0
    while (true) {
      const idx = lower.indexOf(needle, from)
      if (idx < 0) break
      const before = idx === 0 ? '' : lower[idx - 1]
      if (before === '?' || before === '&') return true
      from = idx + 1
    }
  }
  return false
}

module.exports = Object.freeze({
  WU_REASON: WU_REASON,
  WebSocketUrlGuard: WebSocketUrlGuard
})
