'use strict'

// fetchinitcatalogguard.js —— fetch/Request 初始化风险目录。
//
// 威胁模型：
//   mode:'no-cors' 得到不透明响应却常被误用、credentials:'include' 跨源带凭据、redirect:'follow' 自动跟随，
//   组合不当导致泄露或响应伪造。本模块审计 init 选项集合，纯字符，不用正则。

const FIC_REASON = Object.freeze({
  BLOCK: 'fetchinitcatalog-input-hits-blocked-catalog',
  WARN: 'fetchinitcatalog-input-hits-review-catalog',
  PREFIX: 'fetchinitcatalog-input-hits-dangerous-prefix',
  EMPTY: 'fetchinitcatalog-input-is-empty'
})

const FIC_BLOCK = Object.freeze([
  'mode=no-cors-opaque-read',
  'redirect=manual-ignored',
  'cache=no-store-disabled',
])

const FIC_WARN = Object.freeze([
  'credentials=include',
  'redirect=follow',
  'redirect=error-strict-ignore',
  'referrer=unsafe-url',
  'referrerPolicy=unsafe-url',
  'mode=cors-with-include',
])

const FIC_ALLOW = Object.freeze([
  'credentials=same-origin',
  'redirect=error',
  'redirect=manual',
  'referrerPolicy=no-referrer',
  'referrerPolicy=strict-origin-when-cross-origin',
  'mode=cors',
  'cache=default',
])

const FIC_PREFIX_LIT = Object.freeze([
])
const FIC_PREFIX_REASON = Object.freeze([
])

function FICLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FICIn (list, v) {
  for (const x of list) { if (FICLower(x) === v) return true }
  return false
}

function FICSplit (inStr) {
  return inStr.split(',')
}

class FICGuard {
  static get blockList () { return FIC_BLOCK }
  static get warnList () { return FIC_WARN }
  static get allowList () { return FIC_ALLOW }
  static get prefixLit () { return FIC_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: FIC_REASON.EMPTY }] }
    for (const tok of FICSplit(inStr)) {
      const cmp = FICLower(String(tok).trim())
      if (FICIn(FIC_BLOCK, cmp)) findings.push({ reason: FIC_REASON.BLOCK, detail: cmp })
      else if (FICIn(FIC_WARN, cmp)) findings.push({ reason: FIC_REASON.WARN, detail: cmp })
      for (let i = 0; i < FIC_PREFIX_LIT.length; i++) {
        const lit = FIC_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: FIC_REASON.PREFIX, detail: FIC_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  FIC_REASON: FIC_REASON,
  FIC_BLOCK: FIC_BLOCK,
  FIC_WARN: FIC_WARN,
  FIC_ALLOW: FIC_ALLOW,
  FICGuard: FICGuard
})
