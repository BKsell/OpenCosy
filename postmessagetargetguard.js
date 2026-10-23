'use strict'

// postmessagetargetguard.js —— window.postMessage 的 targetOrigin 使用守卫。
//
// 威胁模型：
//   postMessage(msg, '*') 会把数据投递给任何恰好接到该窗口/iframe 的来源。若消息里含令牌、
//   用户数据、内部状态，被导航到攻击者页的接收方就能读到。规则：
//     - 发给跨源窗口：targetOrigin 必须是精确来源，禁止 "*"；
//     - 发给同源窗口：可用 "/"（同源字面量）或精确 origin；
//     - targetOrigin 为 http:// 明文目标在安全页上下文中应拒绝；
//     - 接收侧（onmessage）应校验 event.origin（本模块只负责发送侧 targetOrigin）。

const PMT_REASON = Object.freeze({
  WILDCARD_TARGET: 'pmt-wildcard-target-origin',
  EMPTY_TARGET: 'pmt-empty-target-origin',
  INSECURE_TARGET: 'pmt-insecure-http-target',
  MALFORMED_ORIGIN: 'pmt-malformed-origin'
})

function defaultPmtPolicy () {
  return { allowWildcardSameOrigin: false, requireSecureCrossOrigin: true }
}

function pmtIsOriginLiteral (s) {
  const v = String(s || '')
  if (v === '/') return { sameOrigin: true, ok: true }
  const idx = v.indexOf('://')
  if (idx <= 0) return { sameOrigin: false, ok: false }
  const scheme = v.slice(0, idx).toLowerCase()
  if (scheme !== 'https' && scheme !== 'http') return { sameOrigin: false, ok: false }
  const rest = v.slice(idx + 3)
  if (rest === '' || rest.indexOf('/') >= 0) return { sameOrigin: false, ok: false }
  return { sameOrigin: false, ok: true, scheme: scheme, origin: v.toLowerCase() }
}

class PostMessageTargetGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultPmtPolicy(), policy || {})
  }

  // call: { targetOrigin, sameOriginTarget:boolean, pageSecure:boolean }
  evaluate (call) {
    const c = call || {}
    const pol = this.policy
    const findings = []
    const to = c.targetOrigin
    if (to === null || to === undefined || String(to).trim() === '') {
      findings.push({ reason: PMT_REASON.EMPTY_TARGET })
      return { safe: false, findings }
    }
    const v = String(to).trim()
    if (v === '*') {
      if (c.sameOriginTarget && pol.allowWildcardSameOrigin) {
        return { safe: true, wildcard: true, findings }
      }
      findings.push({ reason: PMT_REASON.WILDCARD_TARGET })
      return { safe: false, wildcard: true, findings }
    }
    const parsed = pmtIsOriginLiteral(v)
    if (v === '/') {
      return { safe: true, sameOrigin: true, findings }
    }
    if (!parsed.ok) {
      findings.push({ reason: PMT_REASON.MALFORMED_ORIGIN, value: v })
      return { safe: false, findings }
    }
    if (pol.requireSecureCrossOrigin && c.pageSecure && parsed.scheme === 'http') {
      findings.push({ reason: PMT_REASON.INSECURE_TARGET })
    }
    return { safe: findings.length === 0, origin: parsed.origin, findings }
  }
}

module.exports = Object.freeze({
  PMT_REASON: PMT_REASON,
  defaultPmtPolicy: defaultPmtPolicy,
  pmtIsOriginLiteral: pmtIsOriginLiteral,
  PostMessageTargetGuard: PostMessageTargetGuard
})
