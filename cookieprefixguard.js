'use strict'

// cookieprefixguard.js —— 出站 Cookie 的 __Host- / __Secure- 前缀一致性守卫。
//
// 威胁模型：
//   __Host- 与 __Secure- 是浏览器规定的"带前缀 cookie"：名称带这些前缀时，浏览器要求其满足更强的
//   属性约束，从而降低子域投毒与会话劫持风险。若服务端/浏览器给敏感 cookie 起了这些名字却没满足
//   属性要求，浏览器会直接拒收，造成鉴权静默失效；反过来，不带前缀却被当成"安全 cookie"使用也
//   会给人虚假安全感。本模块校验前缀与属性匹配：
//     __Host-  ：必须 Secure、Path=/、无 Domain、不得 SameSite=None；
//     __Secure-：必须 Secure。
//   纯字符判定，不使用正则。

const CP_REASON = Object.freeze({
  HOST_NOT_SECURE: 'host-prefix-cookie-must-be-secure',
  HOST_BAD_PATH: 'host-prefix-cookie-path-must-be-slash',
  HOST_HAS_DOMAIN: 'host-prefix-cookie-must-not-set-domain',
  HOST_SAMESITE_NONE: 'host-prefix-cookie-must-not-be-samesite-none',
  SECURE_NOT_SECURE: 'secure-prefix-cookie-must-be-secure',
  PREFIX_NAME_EMPTY: 'cookie-name-empty-after-prefix'
})

const HOST_PREFIX = '__host-'
const SECURE_PREFIX = '__secure-'

function cpLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

// cookie: { name, secure:bool, path, domain(可为''), sameSite:'Strict'|'Lax'|'None'|'' }
function auditCookie (cookie) {
  const findings = []
  const c = cookie || {}
  const lowerName = cpLower(String(c.name))

  if (lowerName.indexOf(HOST_PREFIX) === 0) {
    if (lowerName.length === HOST_PREFIX.length) {
      findings.push({ reason: CP_REASON.PREFIX_NAME_EMPTY })
    }
    if (c.secure !== true) findings.push({ reason: CP_REASON.HOST_NOT_SECURE })
    if (c.path !== '/') findings.push({ reason: CP_REASON.HOST_BAD_PATH, detail: String(c.path) })
    if (c.domain) findings.push({ reason: CP_REASON.HOST_HAS_DOMAIN, detail: String(c.domain) })
    if (cpLower(String(c.sameSite)) === 'none') {
      findings.push({ reason: CP_REASON.HOST_SAMESITE_NONE })
    }
  } else if (lowerName.indexOf(SECURE_PREFIX) === 0) {
    if (lowerName.length === SECURE_PREFIX.length) {
      findings.push({ reason: CP_REASON.PREFIX_NAME_EMPTY })
    }
    if (c.secure !== true) findings.push({ reason: CP_REASON.SECURE_NOT_SECURE })
  }
  return { safe: findings.length === 0, findings: findings }
}

class CookiePrefixGuard {
  audit (cookie) {
    return auditCookie(cookie)
  }
}

module.exports = Object.freeze({
  CP_REASON: CP_REASON,
  HOST_PREFIX: HOST_PREFIX,
  SECURE_PREFIX: SECURE_PREFIX,
  CookiePrefixGuard: CookiePrefixGuard
})
