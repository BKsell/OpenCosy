'use strict'

// sandboxtokencatalogguard.js —— iframe sandbox 令牌风险目录。
//
// 威胁模型：
//   allow-scripts 与 allow-same-origin 同时出现等于撤沙；allow-top-navigation/allow-popups-to-escape 可
//   逃逸。本模块审计 sandbox 属性令牌集合，纯字符，不用正则。

const SBT_REASON = Object.freeze({
  BLOCK: 'sandboxtokencatalog-input-hits-blocked-catalog',
  WARN: 'sandboxtokencatalog-input-hits-review-catalog',
  PREFIX: 'sandboxtokencatalog-input-hits-dangerous-prefix',
  EMPTY: 'sandboxtokencatalog-input-is-empty'
})

const SBT_BLOCK = Object.freeze([
  'allow-top-navigation-by-user-activation-with-escape',
  'allow-downloads-without-user-activation',
])

const SBT_WARN = Object.freeze([
  'allow-scripts',
  'allow-same-origin',
  'allow-top-navigation',
  'allow-popups',
  'allow-forms',
  'allow-modals',
  'allow-orientation-lock',
  'allow-pointer-lock',
  'allow-presentation',
  'allow-popups-to-escape-sandbox',
  'allow-storage-access-by-user-activation',
])

const SBT_ALLOW = Object.freeze([
  'none',
])

const SBT_PREFIX_LIT = Object.freeze([
])
const SBT_PREFIX_REASON = Object.freeze([
])

function SBTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SBTIn (list, v) {
  for (const x of list) { if (SBTLower(x) === v) return true }
  return false
}

function SBTSplit (inStr) {
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

class SBTGuard {
  static get blockList () { return SBT_BLOCK }
  static get warnList () { return SBT_WARN }
  static get allowList () { return SBT_ALLOW }
  static get prefixLit () { return SBT_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: SBT_REASON.EMPTY }] }
    for (const tok of SBTSplit(inStr)) {
      const cmp = SBTLower(String(tok).trim())
      if (SBTIn(SBT_BLOCK, cmp)) findings.push({ reason: SBT_REASON.BLOCK, detail: cmp })
      else if (SBTIn(SBT_WARN, cmp)) findings.push({ reason: SBT_REASON.WARN, detail: cmp })
      for (let i = 0; i < SBT_PREFIX_LIT.length; i++) {
        const lit = SBT_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: SBT_REASON.PREFIX, detail: SBT_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  SBT_REASON: SBT_REASON,
  SBT_BLOCK: SBT_BLOCK,
  SBT_WARN: SBT_WARN,
  SBT_ALLOW: SBT_ALLOW,
  SBTGuard: SBTGuard
})
