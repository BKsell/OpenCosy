'use strict'

// hostheaderguard.js —— Host/:authority 头校验，防 Host 头投毒（缓存投毒/密码重置链接污染）。
//
// 威胁模型：
//   浏览器/内置服务若回显或信任请求 Host 头生成绝对链接（密码重置邮件、缓存键、跳转），
//   攻击者发 Host: evil.com 可让服务生成指向 evil 的链接，或污染共享缓存。风险输入：
//     - Host 含端口但与实际监听端口不符；
//     - 主机名在允许清单之外；
//     - 非法字符（空格、@、绝对 URI 形式）、前导点/双点、IDN 同形由 idnhomoglyphguard 另管；
//     - Host 与 :authority（HTTP/2）不一致。
//   纯字符判定，不使用正则。

const HH_REASON = Object.freeze({
  EMPTY: 'host-header-empty',
  ILLEGAL_CHAR: 'host-header-contains-illegal-character',
  NOT_ALLOWED: 'host-header-hostname-not-in-allowlist',
  PORT_MISMATCH: 'host-header-port-does-not-match-serving-port',
  BAD_PORT: 'host-header-port-not-a-valid-number',
  AUTHORITY_MISMATCH: 'host-header-and-authority-differ',
  LEADING_DOT: 'host-name-has-leading-or-trailing-dot-label'
})

const ILLEGAL_HOST_CHARS = [' ', '\t', '\r', '\n', '@', '/', '\\', '"', '`', '<', '>', '?', '#', '{', '}', '|']

function hhLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

// 拆 host 与 port，兼容 [ipv6]:port。
function hhSplitHostPort (raw) {
  let host = raw
  let port = null
  if (host[0] === '[') {
    const close = host.indexOf(']')
    if (close < 0) return { host: host, port: null, bad: true }
    const v6 = host.slice(1, close)
    const rest = host.slice(close + 1)
    if (rest.length > 0) {
      if (rest[0] !== ':') return { host: v6, port: null, bad: true }
      port = rest.slice(1)
    }
    return { host: v6, port: port, bad: false }
  }
  const colon = host.indexOf(':')
  if (colon >= 0) {
    // 裸 IPv6（无括号）含多个冒号
    if (host.indexOf(':', colon + 1) >= 0) return { host: host, port: null, bad: true }
    port = host.slice(colon + 1)
    host = host.slice(0, colon)
  }
  return { host: host, port: port, bad: false }
}

class HostHeaderGuard {
  // allowedHosts: 主机名小写白名单；servePorts: 允许端口数字数组（默认端口 80/443 也允许）。
  constructor (allowedHosts, servePorts) {
    this.allow = new Set((allowedHosts || []).map(hhLower))
    this.ports = new Set([80, 443].concat(servePorts || []))
  }

  evaluate (input) {
    const inp = input || {}
    const findings = []
    const rawHost = String(inp.hostHeader || '')
    if (rawHost.length === 0) {
      findings.push({ reason: HH_REASON.EMPTY })
      return { safe: false, findings: findings }
    }
    for (const ch of ILLEGAL_HOST_CHARS) {
      if (rawHost.indexOf(ch) >= 0) { findings.push({ reason: HH_REASON.ILLEGAL_CHAR, detail: ch }); break }
    }
    const sp = hhSplitHostPort(rawHost)
    if (sp.bad) findings.push({ reason: HH_REASON.ILLEGAL_CHAR })
    const hostname = hhLower(sp.host)
    if (hostname[0] === '.' || hostname[hostname.length - 1] === '.') {
      findings.push({ reason: HH_REASON.LEADING_DOT })
    }
    if (this.allow.size > 0 && !this.allow.has(hostname)) {
      findings.push({ reason: HH_REASON.NOT_ALLOWED, detail: hostname })
    }
    if (sp.port !== null && sp.port !== '') {
      const portStr = String(sp.port)
      let allDigits = portStr.length > 0
      for (let i = 0; i < portStr.length; i++) {
        const c = portStr.charCodeAt(i)
        if (c < 48 || c > 57) { allDigits = false; break }
      }
      const n = allDigits ? Number(portStr) : NaN
      if (!allDigits || !Number.isInteger(n) || n < 0 || n > 65535) {
        findings.push({ reason: HH_REASON.BAD_PORT })
      } else if (!this.ports.has(n)) {
        findings.push({ reason: HH_REASON.PORT_MISMATCH, detail: String(n) })
      }
    }
    if (inp.authority !== undefined && hhLower(String(inp.authority)) !== hhLower(rawHost)) {
      findings.push({ reason: HH_REASON.AUTHORITY_MISMATCH })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  HH_REASON: HH_REASON,
  hhSplitHostPort: hhSplitHostPort,
  HostHeaderGuard: HostHeaderGuard
})
