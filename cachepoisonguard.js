'use strict'

// cachepoisonguard.js —— 响应缓存键与"不可缓存的输入相关响应"守卫，防 Web 缓存投毒。
//
// 威胁模型：
//   缓存（共享 CDN/浏览器 HTTP 缓存）按 URL+部分请求头做键。若响应内容依赖未进键的请求头
//   （X-Forwarded-Host、X-Forwarded-Scheme、X-Forwarded-For 等），攻击者先投毒，其他用户命中
//   被污染的缓存（链接/脚本地址被改）。规则：
//     - 依赖不可信输入头的响应不得 public 缓存；
//     - 含 Set-Cookie/Authorization 的响应不得共享缓存；
//     - 对带 query 的动态 HTML 默认不缓存；
//     - 30x 到带凭据位置的响应不缓存。
//   纯字符判定，不使用正则。

const CP2_REASON = Object.freeze({
  UNKEYED_HEADER_REFLECTED: 'response-depends-on-unkeyed-request-header-but-public-cacheable',
  SET_COOKIE_CACHED: 'set-cookie-response-marked-public-cacheable',
  AUTH_RESPONSE_CACHED: 'authorization-varying-response-cacheable-without-private',
  DYNAMIC_HTML_CACHED: 'dynamic-html-with-query-marked-public-cacheable',
  REDIRECT_CACHED: 'redirect-response-with-sensitive-location-marked-cacheable'
})

const UNKEYED_HEADERS = [
  'x-forwarded-host', 'x-forwarded-scheme', 'x-forwarded-proto',
  'x-forwarded-port', 'x-forwarded-prefix', 'x-original-url', 'x-rewrite-url',
  'x-host', 'forwarded'
]

function cpLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function cpParamPresent (lowerUrl, key) {
  const needle = key + '='
  let from = 0
  while (true) {
    const idx = lowerUrl.indexOf(needle, from)
    if (idx < 0) return false
    const before = idx === 0 ? '' : lowerUrl[idx - 1]
    if (before === '?' || before === '&') return true
    from = idx + 1
  }
}

function cpParseCacheControl (cc) {
  const out = { public: false, private: false, noStore: false, noCache: false, maxAge: null }
  const parts = String(cc || '').split(',')
  for (let p of parts) {
    p = cpLower(p.trim())
    if (p === 'public') out.public = true
    else if (p === 'private') out.private = true
    else if (p === 'no-store') out.noStore = true
    else if (p === 'no-cache') out.noCache = true
    else if (p.indexOf('max-age=') === 0) out.maxAge = Number(p.slice(8))
  }
  return out
}

class CachePoisonGuard {
  // in: { method, url, status, contentType, cacheControl, setCookie, usedRequestHeaders:[], hasAuthHeader, location }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const cc = cpParseCacheControl(inp.cacheControl)
    const sharedCacheable = cc.public && !cc.private && !cc.noStore && !cc.noCache &&
      (cc.maxAge === null || cc.maxAge > 0)

    const used = (inp.usedRequestHeaders || []).map(cpLower)
    if (sharedCacheable) {
      for (const h of used) {
        if (UNKEYED_HEADERS.indexOf(h) >= 0) {
          findings.push({ reason: CP2_REASON.UNKEYED_HEADER_REFLECTED, detail: h })
        }
      }
      if (inp.setCookie) findings.push({ reason: CP2_REASON.SET_COOKIE_CACHED })
      if (inp.hasAuthHeader) findings.push({ reason: CP2_REASON.AUTH_RESPONSE_CACHED })
      const url = String(inp.url || '')
      const ctype = cpLower(String(inp.contentType || ''))
      if (url.indexOf('?') >= 0 && ctype.indexOf('html') >= 0) {
        findings.push({ reason: CP2_REASON.DYNAMIC_HTML_CACHED })
      }
      const status = Number(inp.status)
      const loc = cpLower(String(inp.location || ''))
      if (status >= 300 && status < 400 &&
          (cpParamPresent(loc, 'token') || cpParamPresent(loc, 'code') || loc.indexOf('@') >= 0)) {
        findings.push({ reason: CP2_REASON.REDIRECT_CACHED })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  CP2_REASON: CP2_REASON,
  UNKEYED_HEADERS: UNKEYED_HEADERS,
  cpParseCacheControl: cpParseCacheControl,
  CachePoisonGuard: CachePoisonGuard
})
