'use strict'

// setcookiesecurityguard.js —— Set-Cookie 安全属性组合守卫。
//
// 威胁模型：
//   会话/凭据类 Cookie 缺少安全属性会被窃取或在明文链路泄露：
//     - 无 Secure：http 链路也会发送，可被中间人劫持；
//     - 无 HttpOnly：document.cookie 可读，XSS 直接偷走会话；
//     - SameSite 缺失或为 None：跨站请求自动携带，CSRF；SameSite=None 还必须带 Secure；
//     - Domain 被设成上级域（如 example.com）：扩大到所有子域，最小权限违规；
//     - Path=/ 之外的可疑宽泛路径；__Host-/__Secure- 前缀有强制要求（RFC 6265bis）：
//         __Host- 必须 Secure + 无 Domain + Path=/；
//         __Secure- 必须 Secure。
//     - 永久 Max-Age 过大（追踪）按策略提示；Expires 已过（清除）不算违规。

const SCS_REASON = Object.freeze({
  MISSING_SECURE: 'scs-missing-secure',
  MISSING_HTTPONLY: 'scs-missing-httponly',
  MISSING_SAMESITE: 'scs-missing-samesite',
  SAMESITE_NONE_WITHOUT_SECURE: 'scs-samesite-none-without-secure',
  INVALID_SAMESITE: 'scs-invalid-samesite',
  BROAD_DOMAIN: 'scs-broad-domain-attribute',
  HOST_PREFIX_VIOLATION: 'scs-host-prefix-violation',
  SECURE_PREFIX_VIOLATION: 'scs-secure-prefix-violation',
  CONTROL_CHAR: 'scs-control-char'
})

function defaultCookiePolicy () {
  return {
    requireSecure: true,
    requireHttpOnly: true,
    requireSameSite: true,
    rejectBroadDomain: true,
    rejectControlChars: true
  }
}

function scsHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1F || c === 0x7F) return true
  }
  return false
}

// 解析单条 Set-Cookie 值（不含 "Set-Cookie: " 前缀）。
function parseSetCookie (value) {
  const raw = String(value || '')
  const parts = raw.split(';')
  const first = parts[0].trim()
  const eq = first.indexOf('=')
  const name = eq < 0 ? first.trim() : first.slice(0, eq).trim()
  const attrs = { secure: false, httpOnly: false, sameSite: null, domain: null, path: null }
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i].trim()
    if (seg === '') continue
    const lower = seg.toLowerCase()
    const aeq = seg.indexOf('=')
    const aname = (aeq < 0 ? lower : lower.slice(0, aeq).trim())
    const aval = aeq < 0 ? null : seg.slice(aeq + 1).trim()
    if (aname === 'secure') attrs.secure = true
    else if (aname === 'httponly') attrs.httpOnly = true
    else if (aname === 'samesite') attrs.sameSite = (aval || '').toLowerCase()
    else if (aname === 'domain') attrs.domain = aval
    else if (aname === 'path') attrs.path = aval
  }
  return { name: name, attrs: attrs }
}

class SetCookieSecurityGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCookiePolicy(), policy || {})
  }

  evaluate (cookieValue) {
    const pol = this.policy
    const findings = []
    if (cookieValue === null || cookieValue === undefined || String(cookieValue).trim() === '') {
      return { safe: false, findings: [{ reason: 'scs-empty' }] }
    }
    const raw = String(cookieValue)
    if (pol.rejectControlChars && scsHasControlChar(raw)) {
      findings.push({ reason: SCS_REASON.CONTROL_CHAR })
    }
    const parsed = parseSetCookie(raw)
    const a = parsed.attrs
    const name = parsed.name
    const lname = name.toLowerCase()

    if (pol.requireSecure && !a.secure) findings.push({ reason: SCS_REASON.MISSING_SECURE, name: name })
    if (pol.requireHttpOnly && !a.httpOnly) findings.push({ reason: SCS_REASON.MISSING_HTTPONLY, name: name })
    if (pol.requireSameSite && !a.sameSite) findings.push({ reason: SCS_REASON.MISSING_SAMESITE, name: name })
    if (a.sameSite) {
      if (a.sameSite === 'none') {
        if (!a.secure) findings.push({ reason: SCS_REASON.SAMESITE_NONE_WITHOUT_SECURE })
      } else if (a.sameSite !== 'lax' && a.sameSite !== 'strict') {
        findings.push({ reason: SCS_REASON.INVALID_SAMESITE, value: a.sameSite })
      }
    }
    if (pol.rejectBroadDomain && a.domain !== null && String(a.domain).trim() !== '') {
      findings.push({ reason: SCS_REASON.BROAD_DOMAIN, domain: a.domain })
    }
    if (lname.indexOf('__host-') === 0) {
      if (!a.secure || a.domain !== null || a.path !== '/') {
        findings.push({ reason: SCS_REASON.HOST_PREFIX_VIOLATION })
      }
    }
    if (lname.indexOf('__secure-') === 0 && !a.secure) {
      findings.push({ reason: SCS_REASON.SECURE_PREFIX_VIOLATION })
    }
    return { safe: findings.length === 0, name: name, attrs: a, findings: findings }
  }
}

module.exports = Object.freeze({
  SCS_REASON: SCS_REASON,
  defaultCookiePolicy: defaultCookiePolicy,
  parseSetCookie: parseSetCookie,
  SetCookieSecurityGuard: SetCookieSecurityGuard
})
