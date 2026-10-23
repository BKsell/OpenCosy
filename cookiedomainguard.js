'use strict'

// cookiedomainguardguard.js —— Cookie Domain/Path/SameSite 作用域守卫。
//
// 威胁模型：
//   Set-Cookie 的 Domain 属性过宽会让子域都能读到会话 cookie；一个被攻陷的低信任子域即可窃取：
//     - Domain=.example.com（前导点）覆盖所有子域；
//     - 不带 HostOnly 却给了公共后缀（co.uk、github.io 一类，禁止设置）；
//     - Path=/ 配敏感会话（至少应收窄 path）；
//     - SameSite 缺失或 None 且未带 Secure（跨站携带，CSRF）；
//     - Secure cookie 被设在 http 响应里。
//   公共后缀用一个小内置清单演示，真实环境应接 PSL。纯字符判定，不使用正则。

const CD_REASON = Object.freeze({
  WILD_SUBDOMAIN_DOMAIN: 'cookie-domain-is-wildcard-parent-with-leading-dot',
  PUBLIC_SUFFIX_DOMAIN: 'cookie-domain-is-a-public-suffix',
  BROAD_PATH: 'sensitive-cookie-set-with-path-root',
  SAMESITE_NONE_WITHOUT_SECURE: 'samesite-none-cookie-must-be-secure',
  SECURE_ON_HTTP: 'secure-cookie-set-in-plaintext-http-response',
  MISSING_SAMESITE: 'session-cookie-missing-samesite'
})

const PUBLIC_SUFFIXES = [
  'com', 'net', 'org', 'co.uk', 'com.cn', 'org.cn', 'net.cn',
  'github.io', 's3.amazonaws.com', 'cloudfront.net'
]

function cdLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function cdHostOf (url) {
  let rest = String(url)
  const sep = rest.indexOf('://')
  if (sep >= 0) rest = rest.slice(sep + 3)
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '/' || rest[i] === '?' || rest[i] === '#') { rest = rest.slice(0, i); break }
  }
  const pc = rest.indexOf(':')
  if (pc >= 0) rest = rest.slice(0, pc)
  return cdLower(rest)
}

function cdEndsWithLabel (host, suffix) {
  if (host === suffix) return true
  return host.length > suffix.length &&
    host.indexOf('.' + suffix) === host.length - suffix.length - 1
}

class CookieDomainGuard {
  // in: { setCookie:{ name,domain,path,sameSite,secure,hostOnly }, responseScheme, requestHost }
  evaluate (input) {
    const inp = input || {}
    const c = inp.setCookie || {}
    const findings = []
    const sensitive = this.isSensitiveName(c.name)

    let domain = c.domain === undefined ? null : cdLower(String(c.domain))
    if (domain !== null && domain.length > 0) {
      if (domain[0] === '.') {
        findings.push({ reason: CD_REASON.WILD_SUBDOMAIN_DOMAIN, detail: domain })
        domain = domain.slice(1)
      }
      for (const suffix of PUBLIC_SUFFIXES) {
        if (domain === suffix) findings.push({ reason: CD_REASON.PUBLIC_SUFFIX_DOMAIN, detail: suffix })
      }
      // domain 必须是请求主机本身或其父域
      if (inp.requestHost) {
        const host = cdHostOf(inp.requestHost)
        if (host && !cdEndsWithLabel(host, domain)) {
          findings.push({ reason: CD_REASON.PUBLIC_SUFFIX_DOMAIN + '-scope' })
        }
      }
    }
    const path = c.path === undefined ? '/' : String(c.path)
    if (sensitive && (path === '/' || path === '')) findings.push({ reason: CD_REASON.BROAD_PATH })

    const sameSite = cdLower(String(c.sameSite || ''))
    if (sensitive && sameSite === '') findings.push({ reason: CD_REASON.MISSING_SAMESITE })
    if (sameSite === 'none' && c.secure !== true) findings.push({ reason: CD_REASON.SAMESITE_NONE_WITHOUT_SECURE })
    if (c.secure === true && String(inp.responseScheme || '').toLowerCase() === 'http') {
      findings.push({ reason: CD_REASON.SECURE_ON_HTTP })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  isSensitiveName (name) {
    const n = cdLower(String(name || ''))
    return n.indexOf('session') >= 0 || n.indexOf('token') >= 0 ||
      n.indexOf('auth') >= 0 || n.indexOf('sid') >= 0 || n.indexOf('login') >= 0
  }
}

module.exports = Object.freeze({
  CD_REASON: CD_REASON,
  PUBLIC_SUFFIXES: PUBLIC_SUFFIXES,
  CookieDomainGuard: CookieDomainGuard
})
