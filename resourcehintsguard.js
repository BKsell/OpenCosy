'use strict'

// resourcehintsguard.js —— 资源提示（resource hints）隐私/泄露守卫。
//
// 威胁模型：
//   <link rel="preconnect"/"dns-prefetch"> 会在用户尚未真正访问时就向目标主机发起 DNS /
//   TCP / TLS，rel="prefetch"/"prerender" 甚至预取内容。风险：
//     - 向第三方域预连接：泄露浏览意图、暴露真实 IP、触发第三方指纹（即使该资源最终没用上）；
//     - http:// 预连接：明文，SNI/DNS 之外还可被中间人观察/篡改；
//     - prerender 到不可信域：后台执行其脚本、带 Cookie，最强泄露面；
//     - 大量无白名单的第三方预连接拖慢并放大追踪。
//   本模块对一组 hint 做来源白名单/协议校验，输出每个风险项。

const RH_REASON = Object.freeze({
  THIRD_PARTY_ORIGIN: 'rh-third-party-origin',
  INSECURE_SCHEME: 'rh-insecure-scheme',
  UNKNOWN_REL: 'rh-unknown-hint-rel',
  MALFORMED_HREF: 'rh-malformed-href',
  PRERENDER_RISK: 'rh-prerender-elevated-risk'
})

const RH_HINT_RELS = Object.freeze({
  preconnect: 1, 'dns-prefetch': 1, prefetch: 1,
  prerender: 2, preload: 1, 'modulepreload': 1
})

function defaultRhPolicy () {
  return { allowedOrigins: [], rejectInsecure: true, rejectThirdParty: false }
}

function rhOriginOf (url) {
  const s = String(url || '')
  const i = s.indexOf('://')
  if (i <= 0) return null
  const scheme = s.slice(0, i).toLowerCase()
  if (scheme !== 'https' && scheme !== 'http') return null
  const rest = s.slice(i + 3)
  if (rest === '') return null
  const slash = rest.indexOf('/')
  const host = slash < 0 ? rest : rest.slice(0, slash)
  return { scheme: scheme, key: scheme + '://' + host.toLowerCase() }
}

class ResourceHintsGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultRhPolicy(), policy || {})
    this.allow = {}
    ;(this.policy.allowedOrigins || []).forEach((o) => {
      const p = rhOriginOf(o)
      if (p) this.allow[p.key] = true
    })
  }

  // hints: [{ rel, href, crossOrigin }]；pageOrigin 可选，用于第三方判定。
  evaluate (hints, pageOrigin) {
    const pol = this.policy
    const findings = []
    const list = Array.isArray(hints) ? hints : []
    const page = rhOriginOf(pageOrigin)
    list.forEach((h) => {
      const rel = String((h && h.rel) || '').toLowerCase()
      if (!RH_HINT_RELS[rel]) {
        findings.push({ reason: RH_REASON.UNKNOWN_REL, rel: rel })
        return
      }
      const origin = rhOriginOf(h && h.href)
      if (!origin) {
        findings.push({ reason: RH_REASON.MALFORMED_HREF, href: h && h.href, rel: rel })
        return
      }
      const isPage = page && origin.key === page.key
      const isAllowed = this.allow[origin.key] === true
      if (!isPage && !isAllowed) {
        if (pol.rejectThirdParty || RH_HINT_RELS[rel] >= 2) {
          findings.push({ reason: RH_REASON.THIRD_PARTY_ORIGIN, origin: origin.key, rel: rel })
        }
      }
      if (pol.rejectInsecure && origin.scheme === 'http') {
        findings.push({ reason: RH_REASON.INSECURE_SCHEME, origin: origin.key, rel: rel })
      }
      if (rel === 'prerender' && !isPage && !isAllowed) {
        findings.push({ reason: RH_REASON.PRERENDER_RISK, origin: origin.key })
      }
    })
    return { safe: findings.length === 0, count: list.length, findings: findings }
  }
}

module.exports = Object.freeze({
  RH_REASON: RH_REASON,
  RH_HINT_RELS: RH_HINT_RELS,
  defaultRhPolicy: defaultRhPolicy,
  rhOriginOf: rhOriginOf,
  ResourceHintsGuard: ResourceHintsGuard
})
