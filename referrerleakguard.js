'use strict'

// referrerleakguard.js —— Referrer-Policy 与跨站 Referer 泄露守卫。
//
// 威胁模型：
//   默认 Referer 会把完整 URL（可能含路径里的会话 id、query 里的 token）带给第三方子资源和跳转。
//   需要按 Referrer-Policy 决定实际外发的 Referer 值：
//     - unsafe-url：任何降级/跨站都发完整 URL（最危险）；
//     - strict-origin / strict-origin-when-cross-origin：跨站或 https→http 只发 origin；
//     - no-referrer：不发；
//     - origin-when-cross-origin（非 strict）：https→http 仍发 origin（有降级泄露）。
//   本模块按策略 + 源/目标协议推导"应发送的 referer"，并审计实际值是否超发。纯字符判定，不使用正则。

const RL2_REASON = Object.freeze({
  UNSAFE_POLICY: 'referrer-policy-is-unsafe-url',
  FULL_URL_TO_CROSS_ORIGIN: 'full-referrer-url-sent-cross-origin',
  FULL_URL_ON_DOWNGRADE: 'referrer-sent-on-https-to-http-downgrade',
  ACTUAL_EXCEEDS_POLICY: 'actual-referrer-reveals-more-than-policy-allows'
})

function rlLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function rlOriginOf (url) {
  const sep = String(url).indexOf('://')
  if (sep < 0) return ''
  let rest = String(url).slice(sep + 3)
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '/' || rest[i] === '?' || rest[i] === '#') { rest = rest.slice(0, i); break }
  }
  return String(url).slice(0, sep + 3) + rest
}

function rlHostOf (url) {
  let rest = String(url)
  const sep = rest.indexOf('://')
  if (sep >= 0) rest = rest.slice(sep + 3)
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '/' || rest[i] === '?' || rest[i] === '#') { rest = rest.slice(0, i); break }
  }
  const pc = rest.indexOf(':')
  if (pc >= 0) rest = rest.slice(0, pc)
  return rlLower(rest)
}

function rlScheme (url) {
  const sep = String(url).indexOf('://')
  return sep < 0 ? '' : rlLower(String(url).slice(0, sep))
}

class ReferrerLeakGuard {
  // policy：Referrer-Policy；in: { sourceUrl, targetUrl, actualReferrer }
  deriveAllowed (policy, sourceUrl, targetUrl) {
    const crossOrigin = rlHostOf(sourceUrl) !== rlHostOf(targetUrl)
    const downgrade = rlScheme(sourceUrl) === 'https' && rlScheme(targetUrl) === 'http'
    switch (rlLower(String(policy || 'strict-origin-when-cross-origin'))) {
      case 'no-referrer':
        return { value: null, crossOrigin: crossOrigin, downgrade: downgrade }
      case 'same-origin':
        return { value: crossOrigin ? null : sourceUrl, crossOrigin: crossOrigin, downgrade: downgrade }
      case 'origin':
        return { value: rlOriginOf(sourceUrl), crossOrigin: crossOrigin, downgrade: downgrade }
      case 'origin-when-cross-origin':
        // 非 strict：降级时仍发 origin
        return { value: crossOrigin ? rlOriginOf(sourceUrl) : sourceUrl, crossOrigin: crossOrigin, downgrade: downgrade }
      case 'strict-origin':
        return { value: downgrade ? null : rlOriginOf(sourceUrl), crossOrigin: crossOrigin, downgrade: downgrade }
      case 'strict-origin-when-cross-origin':
        if (downgrade) return { value: null, crossOrigin: crossOrigin, downgrade: downgrade }
        return { value: crossOrigin ? rlOriginOf(sourceUrl) : sourceUrl, crossOrigin: crossOrigin, downgrade: downgrade }
      case 'no-referrer-when-downgrade':
        return { value: downgrade ? null : sourceUrl, crossOrigin: crossOrigin, downgrade: downgrade }
      case 'unsafe-url':
        return { value: sourceUrl, crossOrigin: crossOrigin, downgrade: downgrade, unsafe: true }
      default:
        return { value: crossOrigin ? rlOriginOf(sourceUrl) : sourceUrl, crossOrigin: crossOrigin, downgrade: downgrade }
    }
  }

  evaluate (input) {
    const inp = input || {}
    const findings = []
    const policy = rlLower(String(inp.policy || 'strict-origin-when-cross-origin'))
    if (policy === 'unsafe-url') findings.push({ reason: RL2_REASON.UNSAFE_POLICY })
    const allowed = this.deriveAllowed(policy, inp.sourceUrl, inp.targetUrl)
    if (policy === 'unsafe-url') {
      if (allowed.crossOrigin) findings.push({ reason: RL2_REASON.FULL_URL_TO_CROSS_ORIGIN })
      if (allowed.downgrade) findings.push({ reason: RL2_REASON.FULL_URL_ON_DOWNGRADE })
    }
    // 实际 referer 不得比策略允许值暴露更多（更长即可能含路径/query）。
    if (inp.actualReferrer !== undefined) {
      const actual = String(inp.actualReferrer || '')
      if (allowed.value === null) {
        if (actual.length > 0) findings.push({ reason: RL2_REASON.ACTUAL_EXCEEDS_POLICY })
      } else if (actual.length > allowed.value.length) {
        findings.push({ reason: RL2_REASON.ACTUAL_EXCEEDS_POLICY })
      }
    }
    return { safe: findings.length === 0, findings: findings, allowedReferrer: allowed.value }
  }
}

module.exports = Object.freeze({
  RL2_REASON: RL2_REASON,
  ReferrerLeakGuard: ReferrerLeakGuard
})
