'use strict'

// websocketoriginguard.js —— WebSocket 握手 Origin 校验守卫（CSWSH 防护）。
//
// 威胁模型：
//   跨站 WebSocket 劫持（CSWSH）：恶意页面用受害者浏览器的 Cookie 向 wss://api 发起 WS 握手，
//   浏览器会自动带凭据。服务端若不校验 Origin 头，任意网站都能建立已认证的双向通道。
// 校验要点：
//   - Origin 缺失：非浏览器客户端可能没有，浏览器请求必须有；按策略拒绝或单独标记；
//   - Origin 为 "null"（sandbox/data/file 页）：默认拒绝，除非显式允许；
//   - Origin 不在白名单（精确 scheme+host+port，不能后缀匹配被 aevil.com 绕过）；
//   - http/https scheme 与 ws/wss 目标的安全级别是否匹配（https 页连 ws 属混合内容，另见 MC）。
//
// 本模块做白名单精确匹配与结论输出，供 WS 服务端在 upgrade 握手时调用。

const WSO_REASON = Object.freeze({
  ORIGIN_MISSING: 'wso-origin-missing',
  ORIGIN_NULL: 'wso-origin-null',
  ORIGIN_NOT_ALLOWED: 'wso-origin-not-allowed',
  ORIGIN_MALFORMED: 'wso-origin-malformed',
  SCHEME_MISMATCH: 'wso-origin-scheme-mismatch',
  CONTROL_CHAR: 'wso-control-char'
})

function defaultWsOriginPolicy () {
  return {
    allowedOrigins: [],
    allowNullOrigin: false,
    allowMissingOrigin: false, // 浏览器外客户端由调用方显式放行
    requireTlsMatch: true,
    rejectControlChars: true
  }
}

function wsoHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

// 把 origin 归一为小写 {scheme, host, port}。失败返回 null。
function wsoParseOrigin (origin) {
  const s = String(origin || '')
  const idx = s.indexOf('://')
  if (idx <= 0) return null
  const scheme = s.slice(0, idx).toLowerCase()
  if (scheme !== 'https' && scheme !== 'http') return null
  const hostPort = s.slice(idx + 3)
  if (hostPort === '' || hostPort.indexOf('/') >= 0) return null
  let host = hostPort
  let port = null
  // IPv6 [::1]:8080
  if (hostPort.charAt(0) === '[') {
    const close = hostPort.indexOf(']')
    if (close < 0) return null
    host = hostPort.slice(0, close + 1).toLowerCase()
    const rest = hostPort.slice(close + 1)
    if (rest === '') { port = null } else if (rest.charAt(0) === ':') {
      port = rest.slice(1)
    } else return null
  } else {
    const colon = hostPort.lastIndexOf(':')
    if (colon >= 0) {
      host = hostPort.slice(0, colon).toLowerCase()
      port = hostPort.slice(colon + 1)
    } else {
      host = hostPort.toLowerCase()
    }
  }
  if (host === '') return null
  return { scheme: scheme, host: host, port: port, key: scheme + '://' + hostPort.toLowerCase() }
}

function wsoDefaultPort (scheme) {
  return scheme === 'https' ? '443' : '80'
}

class WebSocketOriginGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultWsOriginPolicy(), policy || {})
    this.allowKeys = {}
    ;(this.policy.allowedOrigins || []).forEach((o) => {
      const parsed = wsoParseOrigin(o)
      if (parsed) this.allowKeys[parsed.key] = true
    })
  }

  // origin：握手 Origin 头；targetScheme：'wss'/'ws'。
  evaluate (origin, targetScheme) {
    const pol = this.policy
    const findings = []
    if (origin === null || origin === undefined || String(origin).trim() === '') {
      if (!pol.allowMissingOrigin) findings.push({ reason: WSO_REASON.ORIGIN_MISSING })
      return { safe: pol.allowMissingOrigin, findings }
    }
    const origRaw = String(origin)
    const raw = origRaw.trim()
    if (pol.rejectControlChars && wsoHasControlChar(origRaw)) {
      findings.push({ reason: WSO_REASON.CONTROL_CHAR })
    }
    if (raw === 'null') {
      if (!pol.allowNullOrigin) findings.push({ reason: WSO_REASON.ORIGIN_NULL })
      return { safe: findings.length === 0 && pol.allowNullOrigin, findings }
    }
    const parsed = wsoParseOrigin(raw)
    if (!parsed) {
      findings.push({ reason: WSO_REASON.ORIGIN_MALFORMED, value: raw })
      return { safe: false, findings }
    }
    if (!this.allowKeys[parsed.key]) {
      findings.push({ reason: WSO_REASON.ORIGIN_NOT_ALLOWED, origin: parsed.key })
    }
    if (pol.requireTlsMatch && targetScheme) {
      const ts = String(targetScheme).toLowerCase()
      if (ts === 'wss' && parsed.scheme !== 'https') {
        findings.push({ reason: WSO_REASON.SCHEME_MISMATCH })
      }
      if (ts === 'ws' && parsed.scheme === 'https') {
        findings.push({ reason: WSO_REASON.SCHEME_MISMATCH })
      }
    }
    return { safe: findings.length === 0, origin: parsed.key, findings }
  }
}

module.exports = Object.freeze({
  WSO_REASON: WSO_REASON,
  defaultWsOriginPolicy: defaultWsOriginPolicy,
  wsoParseOrigin: wsoParseOrigin,
  wsoDefaultPort: wsoDefaultPort,
  WebSocketOriginGuard: WebSocketOriginGuard
})
