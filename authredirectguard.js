'use strict'

// authredirectguard.js —— 登录/OAuth 流程中的开放重定向与会话固定守卫。
//
// 威胁模型：
//   登录后常按 ?next=/... 或 ?redirect_uri=... 跳转。若不校验目标：
//     - 开放重定向到钓鱼站（登录后被带去假页面再骗一次）；
//     - 用 //evil.com 协议相对 URL 或反斜杠绕过；
//     - 跳到 javascript:/data:；
//     - 登录前后会话标识不变（session fixation）；
//     - 授权码/token 随跳转离开认证主机。
//   本模块审计登录后跳转目标，并校验会话是否轮换。纯字符判定，不使用正则。

const AR_REASON = Object.freeze({
  ABSOLUTE_TO_FOREIGN_HOST: 'post-login-redirect-to-foreign-absolute-url',
  PROTOCOL_RELATIVE: 'post-login-redirect-uses-protocol-relative-url',
  DANGEROUS_SCHEME: 'post-login-redirect-uses-non-http-scheme',
  BACKSLASH_BYPASS: 'redirect-uses-backslash-to-evade-host-check',
  SESSION_NOT_ROTATED: 'session-id-not-rotated-after-authentication',
  TOKEN_LEAVING_HOST: 'credential-redirects-off-the-authenticating-host'
})

const SAFE_SCHEMES = ['http:', 'https:']

function arLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function arIndexAny (s, chars) {
  for (let i = 0; i < s.length; i++) if (chars.indexOf(s[i]) >= 0) return i
  return -1
}

function arHostname (url) {
  let rest = String(url)
  const colon = rest.indexOf('://')
  if (colon >= 0) rest = rest.slice(colon + 3)
  const end = arIndexAny(rest, ['/', '?', '#'])
  if (end >= 0) rest = rest.slice(0, end)
  if (rest[0] === '[') {
    const c = rest.indexOf(']')
    return c >= 0 ? arLower(rest.slice(1, c)) : arLower(rest)
  }
  const pc = rest.indexOf(':')
  if (pc >= 0) rest = rest.slice(0, pc)
  return arLower(rest)
}

class AuthRedirectGuard {
  // appHost：登录所在主机；跳转只允许站内相对路径或该主机绝对 URL。
  constructor (appHost) {
    this.appHost = arLower(String(appHost || ''))
  }

  evaluate (input) {
    const inp = input || {}
    const findings = []
    const target = String(inp.target || '')
    const low = arLower(target)

    if (target.indexOf('\\') >= 0 && (low.indexOf('\\/') === 0 || low.indexOf('/\\') === 0)) {
      findings.push({ reason: AR_REASON.BACKSLASH_BYPASS })
    }
    if (low.indexOf('//') === 0 || low.indexOf('\\\\') === 0 || low.indexOf('/\\') === 0) {
      findings.push({ reason: AR_REASON.PROTOCOL_RELATIVE })
    }
    const firstSeg = arIndexAny(target, ['/', '?', '#'])
    const colon = low.indexOf(':')
    const hasScheme = colon >= 0 && (firstSeg < 0 || colon < firstSeg)
    if (hasScheme) {
      const scheme = low.slice(0, colon + 1)
      if (SAFE_SCHEMES.indexOf(scheme) < 0) {
        findings.push({ reason: AR_REASON.DANGEROUS_SCHEME, detail: scheme })
      } else if (this.appHost && arHostname(target) !== this.appHost) {
        findings.push({ reason: AR_REASON.ABSOLUTE_TO_FOREIGN_HOST })
      }
    }
    if (inp.sessionBefore !== undefined && inp.sessionAfter !== undefined) {
      if (inp.authenticated && String(inp.sessionBefore) === String(inp.sessionAfter)) {
        findings.push({ reason: AR_REASON.SESSION_NOT_ROTATED })
      }
    }
    if (inp.targetCarriesToken && hasScheme && this.appHost && arHostname(target) !== this.appHost) {
      findings.push({ reason: AR_REASON.TOKEN_LEAVING_HOST })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  AR_REASON: AR_REASON,
  AuthRedirectGuard: AuthRedirectGuard
})
