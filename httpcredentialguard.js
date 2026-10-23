'use strict'

// httpcredentialguard.js —— URL 内嵌凭据与 Authorization 头处理守卫。
//
// 威胁模型：
//   https://user:pass@host 这种 userinfo 会把口令放进 URL：进入历史记录、代理日志、Referer、崩溃
//   报告，且可被同形字符诱导。浏览器默认禁止，但内置下载器/代理拼接可能仍接受。此外：
//     - Authorization 头被转发到重定向后的不同主机（凭据泄露给第三方）；
//     - 明文 http 上携带 Basic/Digest/令牌；
//     - 把口令写进 query。
//   本模块审计 URL userinfo、跨主机是否应剥离 Authorization、scheme 与认证方案组合。
//   纯字符判定，不使用正则。

const HC_REASON = Object.freeze({
  URL_USERINFO: 'url-contains-userinfo-credentials',
  CREDS_FOLLOW_CROSS_HOST: 'authorization-header-follows-cross-host-redirect',
  CREDS_OVER_HTTP: 'authorization-sent-over-plaintext-http',
  BASIC_OVER_HTTP: 'basic-auth-over-http',
  TOKEN_IN_QUERY: 'credential-token-placed-in-url-query',
  WEAK_SCHEME: 'weak-authorization-scheme'
})

const STRONG_SCHEMES = ['basic', 'digest', 'bearer', 'negotiate', 'token']
const SECRET_KEYS = ['password', 'passwd', 'secret', 'token', 'access_token', 'api_key', 'apikey', 'client_secret']

function hcLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

// 从 URL 的 authority 中判断是否含 '@'（即 userinfo）。
function hcHasUserInfo (url) {
  const sep = String(url).indexOf('://')
  if (sep < 0) return false
  let auth = String(url).slice(sep + 3)
  const end = hcIndexAny(auth, ['/', '?', '#'])
  if (end >= 0) auth = auth.slice(0, end)
  // IPv6 地址里没有 @，直接查最后一个 @ 即可
  return auth.indexOf('@') >= 0
}

function hcIndexAny (s, chars) {
  for (let i = 0; i < s.length; i++) if (chars.indexOf(s[i]) >= 0) return i
  return -1
}

function hcHostOf (url) {
  const sep = String(url).indexOf('://')
  if (sep < 0) return ''
  let auth = String(url).slice(sep + 3)
  const end = hcIndexAny(auth, ['/', '?', '#'])
  if (end >= 0) auth = auth.slice(0, end)
  if (auth.indexOf('@') >= 0) auth = auth.slice(auth.lastIndexOf('@') + 1)
  if (auth[0] === '[') {
    const c = auth.indexOf(']')
    return c >= 0 ? hcLower(auth.slice(1, c)) : hcLower(auth)
  }
  const colon = auth.indexOf(':')
  if (colon >= 0) auth = auth.slice(0, colon)
  return hcLower(auth)
}

function hcSchemeOf (url) {
  const sep = String(url).indexOf('://')
  return sep < 0 ? '' : hcLower(String(url).slice(0, sep))
}

class HttpCredentialGuard {
  // in: { url, authorizationScheme, query, redirectFrom(url 可选) }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const url = String(inp.url || '')
    if (hcHasUserInfo(url)) findings.push({ reason: HC_REASON.URL_USERINFO })

    const scheme = hcSchemeOf(url)
    const authScheme = hcLower(String(inp.authorizationScheme || ''))
    if (authScheme) {
      if (STRONG_SCHEMES.indexOf(authScheme) < 0) findings.push({ reason: HC_REASON.WEAK_SCHEME, detail: authScheme })
      if (scheme === 'http') {
        findings.push({ reason: HC_REASON.CREDS_OVER_HTTP })
        if (authScheme === 'basic') findings.push({ reason: HC_REASON.BASIC_OVER_HTTP })
      }
    }
    if (inp.redirectFrom) {
      const before = hcHostOf(inp.redirectFrom)
      const after = hcHostOf(url)
      if (before && after && before !== after && authScheme) {
        findings.push({ reason: HC_REASON.CREDS_FOLLOW_CROSS_HOST })
      }
    }
    let query = hcLower(String(inp.query || ''))
    if (!query) {
      const q = String(url).indexOf('?')
      if (q >= 0) query = hcLower(String(url).slice(q))
    }
    for (const k of SECRET_KEYS) {
      const needle = k + '='
      let from = 0
      while (true) {
        const idx = query.indexOf(needle, from)
        if (idx < 0) break
        const before = idx === 0 ? '' : query[idx - 1]
        if (before === '?' || before === '&') {
          findings.push({ reason: HC_REASON.TOKEN_IN_QUERY, detail: k })
          break
        }
        from = idx + 1
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  HC_REASON: HC_REASON,
  hcHasUserInfo: hcHasUserInfo,
  hcHostOf: hcHostOf,
  HttpCredentialGuard: HttpCredentialGuard
})
