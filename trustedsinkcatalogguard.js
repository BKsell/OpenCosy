'use strict'

// trustedsinkcatalogguard.js —— Trusted Types 策略 sink 目录。
//
// 威胁模型：
//   强制 Trusted Types 后仅策略对象可写 HTML sink；绕过策略的默认策略与裸 sink 赋值应拦。本模块按 sink 名
//   分级，纯字符，不用正则。

const TSG_REASON = Object.freeze({
  BLOCK: 'trustedsinkcatalog-input-hits-blocked-catalog',
  WARN: 'trustedsinkcatalog-input-hits-review-catalog',
  PREFIX: 'trustedsinkcatalog-input-hits-dangerous-prefix',
  EMPTY: 'trustedsinkcatalog-input-is-empty'
})

const TSG_BLOCK = Object.freeze([
  'createHTML(\'unsafe\')',
  'createScriptURL(\'unsafe\')',
  'default-policy-removes-guard',
  'trustedTypes.createPolicy(\'default\',-allow-all)',
  'innerHTML=raw-string',
])

const TSG_WARN = Object.freeze([
  'createHTML',
  'createScriptURL',
  'createPolicy',
  'default',
])

const TSG_ALLOW = Object.freeze([
  'textContent-assign',
  'policy.createHTML-reviewed',
  'sanitized-html',
])

const TSG_PREFIX_LIT = Object.freeze([
])
const TSG_PREFIX_REASON = Object.freeze([
])

function TSGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function TSGIn (list, v) {
  for (const x of list) { if (TSGLower(x) === v) return true }
  return false
}

function TSGSplit (inStr) {
  const out = []
  let start = -1
  for (let i = 0; i <= inStr.length; i++) {
    const end = i === inStr.length
  let sep = false
    if (!end) { const c = inStr[i]; sep = c === ' ' || c === '\t' || c === '\n' || c === '\r' }
    if (end || sep) { if (start >= 0) { out.push(inStr.slice(start, i)); start = -1 } }
    else if (start < 0) { start = i } }
  return out
}

class TSGGuard {
  static get blockList () { return TSG_BLOCK }
  static get warnList () { return TSG_WARN }
  static get allowList () { return TSG_ALLOW }
  static get prefixLit () { return TSG_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: TSG_REASON.EMPTY }] }
    for (const tok of TSGSplit(inStr)) {
      const cmp = TSGLower(String(tok).trim())
      if (TSGIn(TSG_BLOCK, cmp)) findings.push({ reason: TSG_REASON.BLOCK, detail: cmp })
      else if (TSGIn(TSG_WARN, cmp)) findings.push({ reason: TSG_REASON.WARN, detail: cmp })
      for (let i = 0; i < TSG_PREFIX_LIT.length; i++) {
        const lit = TSG_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: TSG_REASON.PREFIX, detail: TSG_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  TSG_REASON: TSG_REASON,
  TSG_BLOCK: TSG_BLOCK,
  TSG_WARN: TSG_WARN,
  TSG_ALLOW: TSG_ALLOW,
  TSGGuard: TSGGuard
})
