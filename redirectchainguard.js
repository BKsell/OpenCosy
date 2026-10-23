'use strict'

// redirectchainguard.js —— 多级重定向链的收敛与开放重定向守卫。
//
// 威胁模型：
//   浏览器/下载器跟随 3xx。攻击者可让可信域名 302 到不可信主机（open redirect），或经过多跳把
//   最终落点切到 file:、内网 IP、非 http(s) scheme；跨 scheme 降级（https→http）会丢安全上下文。
//   本模块审计一条重定向链 [url0 -> url1 -> ... -> final]：
//     - 任意一跳跳到非 http(s)；
//     - 任一跳目标主机是内网/环回（结合 ipliteralguard）；
//     - https 降级到 http；
//     - 跳数超限、链中出现重复 URL（重定向环）。
//   URL 解析做最小手工拆分，不使用正则。

const { ilClassifyV4 } = require('./ipliteralguard.js')

const RC_REASON = Object.freeze({
  NON_HTTP_TARGET: 'redirect-target-scheme-not-http-or-https',
  DOWNGRADE: 'redirect-downgrades-https-to-http',
  INTERNAL_TARGET: 'redirect-target-host-is-internal-ip',
  TOO_MANY_HOPS: 'redirect-chain-exceeds-hop-limit',
  REDIRECT_LOOP: 'redirect-chain-contains-repeated-url',
  EMPTY_URL: 'redirect-target-url-empty'
})

const INTERNAL = new Set(['loopback', 'private', 'linklocal'])

function rcSchemeHost (url) {
  let rest = String(url)
  // 去 fragment
  const h = rest.indexOf('#')
  if (h >= 0) rest = rest.slice(0, h)
  const sep = rest.indexOf('://')
  if (sep < 0) return { scheme: '', host: '' }
  const scheme = rest.slice(0, sep).toLowerCase()
  let authority = rest.slice(sep + 3)
  const slash = rcIndexAny(authority, ['/', '?', '#'])
  if (slash >= 0) authority = authority.slice(0, slash)
  let host = authority
  // 去 userinfo
  const at = host.lastIndexOf('@')
  if (at >= 0) host = host.slice(at + 1)
  // 去端口 / 方括号
  if (host[0] === '[') {
    const close = host.indexOf(']')
    host = close >= 0 ? host.slice(1, close) : host
  } else {
    const colon = host.indexOf(':')
    if (colon >= 0) host = host.slice(0, colon)
  }
  return { scheme: scheme, host: host }
}

function rcIndexAny (s, chars) {
  for (let i = 0; i < s.length; i++) {
    if (chars.indexOf(s[i]) >= 0) return i
  }
  return -1
}

function rcHasNonAscii (s) {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 127) return true
  }
  return false
}

class RedirectChainGuard {
  constructor (maxHops) {
    this.maxHops = typeof maxHops === 'number' ? maxHops : 5
  }

  // chain: 完整 URL 数组，包含起点与每一跳目标。
  audit (chain) {
    const findings = []
    const urls = chain || []
    if (urls.length === 0) {
      findings.push({ reason: RC_REASON.EMPTY_URL })
      return { safe: false, findings: findings }
    }
    if (urls.length - 1 > this.maxHops) findings.push({ reason: RC_REASON.TOO_MANY_HOPS })

    const seen = new Set()
    let prevScheme = ''
    for (const url of urls) {
      if (!url) {
        findings.push({ reason: RC_REASON.EMPTY_URL })
        continue
      }
      if (seen.has(url)) findings.push({ reason: RC_REASON.REDIRECT_LOOP, detail: url })
      seen.add(url)

      const sh = rcSchemeHost(url)
      if (sh.scheme !== 'http' && sh.scheme !== 'https') {
        findings.push({ reason: RC_REASON.NON_HTTP_TARGET, detail: sh.scheme || url })
      }
      if (prevScheme === 'https' && sh.scheme === 'http') {
        findings.push({ reason: RC_REASON.DOWNGRADE })
      }
      if (sh.host && !rcHasNonAscii(sh.host)) {
        const cls = ilClassifyV4(sh.host)
        if (INTERNAL.has(cls)) findings.push({ reason: RC_REASON.INTERNAL_TARGET, detail: sh.host })
      }
      if (sh.scheme) prevScheme = sh.scheme
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  RC_REASON: RC_REASON,
  RedirectChainGuard: RedirectChainGuard,
  rcSchemeHost: rcSchemeHost
})
