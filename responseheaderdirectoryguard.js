'use strict'

// responseheaderdirectoryguard.js —— HTTP 响应头安全分级目录。
//
// 威胁模型：
//   安全隔离头（CSP/COOP/CORP/HSTS 等）应存在且强，暴露内部信息或允许跨源的头需复核，缓存/协商头常规。
//   纯字符查表，不用正则。

const RHD_REASON = Object.freeze({
  BLOCK: 'responseheaderdirectory-input-hits-blocked-catalog',
  WARN: 'responseheaderdirectory-input-hits-review-catalog',
  PREFIX: 'responseheaderdirectory-input-hits-dangerous-prefix',
  EMPTY: 'responseheaderdirectory-input-is-empty'
})

const RHD_BLOCK = Object.freeze([
  'Server',
  'X-Powered-By',
  'X-AspNet-Version',
  'X-AspNetMvc-Version',
  'X-Generator',
  'X-Drupal-Cache',
  'X-Served-By',
  'X-Backend-Server',
  'Via',
  'X-Application-Context',
  'X-Envoy-Upstream-Service-Time',
  'X-Runtime',
  'X-Request-Id',
  'X-Correlation-Id',
  'X-Trace-Id',
  'X-Amzn-Trace-Id',
  'X-Amz-Cf-Id',
  'X-Varnish',
  'X-Cache',
  'X-Cache-Info',
  'X-Debug',
  'X-Debug-Token',
  'X-Exception',
  'X-Error',
  'X-Error-Detail',
  'X-Response-Time',
  'X-Upstream',
  'X-Upstream-Latency',
  'X-Kong-Upstream-Latency',
  'X-Kong-Proxy-Latency',
  'X-Forwarded-Host',
  'X-Frame-Options',
  'Access-Control-Allow-Origin',
  'Access-Control-Allow-Credentials',
])

const RHD_WARN = Object.freeze([
  'Access-Control-Allow-Methods',
  'Access-Control-Allow-Headers',
  'Access-Control-Expose-Headers',
  'Access-Control-Max-Age',
  'Access-Control-Request-Method',
  'Access-Control-Request-Headers',
  'Timing-Allow-Origin',
  'Cross-Origin-Window-Policy',
  'X-WebKit-CSP',
  'X-Content-Security-Policy',
  'X-XSS-Protection',
  'X-DNS-Prefetch-Control',
  'X-Permitted-Cross-Domain-Policies',
  'X-UA-Compatible',
  'Set-Cookie',
  'Set-Cookie2',
  'Location',
  'Refresh',
  'Content-Security-Policy-Report-Only',
  'Expect-CT',
  'Report-To',
  'NEL',
  'Reporting-Endpoints',
  'X-Pingback',
  'X-Page-Location',
  'X-Translated-By',
  'X-Recruiting',
  'X-SourceMap',
  'SourceMap',
  'X-SourceMap-From',
])

const RHD_ALLOW = Object.freeze([
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Embedder-Policy',
  'Cross-Origin-Resource-Policy',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
  'Cache-Control',
  'Pragma',
  'Expires',
  'Date',
  'Age',
  'ETag',
  'Last-Modified',
  'Vary',
  'Warning',
  'Content-Type',
  'Content-Length',
  'Content-Encoding',
  'Content-Language',
  'Content-Location',
  'Content-Disposition',
  'Content-Range',
  'Accept-Ranges',
  'Allow',
  'Retry-After',
  'Server-Timing',
  'Link',
  'Alt-Svc',
  'Connection',
  'Keep-Alive',
  'Transfer-Encoding',
  'Trailer',
  'Upgrade',
  'Early-Data',
  'Accept-Patch',
  'Accept-Post',
  'Clear-Site-Data',
  'Origin-Agent-Cluster',
  'X-Frame-Options.strong',
])

const RHD_PREFIX_LIT = Object.freeze([
])
const RHD_PREFIX_REASON = Object.freeze([
])

function RHDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function RHDIn (list, v) {
  for (const x of list) { if (RHDLower(x) === v) return true }
  return false
}

function RHDSplit (inStr) {
  return inStr.split(',')
}

class RHDGuard {
  static get blockList () { return RHD_BLOCK }
  static get warnList () { return RHD_WARN }
  static get allowList () { return RHD_ALLOW }
  static get prefixLit () { return RHD_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: RHD_REASON.EMPTY }] }
    for (const tok of RHDSplit(inStr)) {
      const cmp = RHDLower(String(tok).trim())
      if (RHDIn(RHD_BLOCK, cmp)) findings.push({ reason: RHD_REASON.BLOCK, detail: cmp })
      else if (RHDIn(RHD_WARN, cmp)) findings.push({ reason: RHD_REASON.WARN, detail: cmp })
      for (let i = 0; i < RHD_PREFIX_LIT.length; i++) {
        const lit = RHD_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: RHD_REASON.PREFIX, detail: RHD_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  RHD_REASON: RHD_REASON,
  RHD_BLOCK: RHD_BLOCK,
  RHD_WARN: RHD_WARN,
  RHD_ALLOW: RHD_ALLOW,
  RHDGuard: RHDGuard
})
