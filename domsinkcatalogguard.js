'use strict'

// domsinkcatalogguard.js —— 危险 DOM Sink 属性/方法目录。
//
// 威胁模型：
//   把不可信字符串写入 innerHTML/outerHTML/src/href、setAttribute 的事件/URL 属性都会形成 XSS。本模块
//   审计 sink 名集合，纯字符，不用正则。

const DSK_REASON = Object.freeze({
  BLOCK: 'domsinkcatalog-input-hits-blocked-catalog',
  WARN: 'domsinkcatalog-input-hits-review-catalog',
  PREFIX: 'domsinkcatalog-input-hits-dangerous-prefix',
  EMPTY: 'domsinkcatalog-input-is-empty'
})

const DSK_BLOCK = Object.freeze([
  'innerHTML',
  'outerHTML',
  'document.write',
  'document.writeln',
  'insertAdjacentHTML',
  'setAttribute(\'onclick\')',
  'src=javascript:',
  'href=javascript:',
  'src=vbscript:',
  'formaction',
  'xlink:href',
  'styleSheet.cssText',
  'style.cssText',
  'Range.createContextualFragment',
])

const DSK_WARN = Object.freeze([
  'setAttribute',
  'setAttributeNS',
  'srcdoc',
  'location.assign',
  'location.replace',
  'window.open',
  'anchor.href',
  'script.src',
  'iframe.src',
  'base.href',
])

const DSK_ALLOW = Object.freeze([
  'textContent',
  'innerText',
  'nodeValue',
  'setAttribute(\'class\')',
  'classList.add',
  'dataset.id',
  'setAttribute(\'role\')',
  'getAttribute',
  'appendChild',
  'removeChild',
])

const DSK_PREFIX_LIT = Object.freeze([
])
const DSK_PREFIX_REASON = Object.freeze([
])

function DSKLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DSKIn (list, v) {
  for (const x of list) { if (DSKLower(x) === v) return true }
  return false
}

function DSKSplit (inStr) {
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

class DSKGuard {
  static get blockList () { return DSK_BLOCK }
  static get warnList () { return DSK_WARN }
  static get allowList () { return DSK_ALLOW }
  static get prefixLit () { return DSK_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: DSK_REASON.EMPTY }] }
    for (const tok of DSKSplit(inStr)) {
      const cmp = DSKLower(String(tok).trim())
      if (DSKIn(DSK_BLOCK, cmp)) findings.push({ reason: DSK_REASON.BLOCK, detail: cmp })
      else if (DSKIn(DSK_WARN, cmp)) findings.push({ reason: DSK_REASON.WARN, detail: cmp })
      for (let i = 0; i < DSK_PREFIX_LIT.length; i++) {
        const lit = DSK_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: DSK_REASON.PREFIX, detail: DSK_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  DSK_REASON: DSK_REASON,
  DSK_BLOCK: DSK_BLOCK,
  DSK_WARN: DSK_WARN,
  DSK_ALLOW: DSK_ALLOW,
  DSKGuard: DSKGuard
})
