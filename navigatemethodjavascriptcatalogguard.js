'use strict'

// navigatemethodjavascriptcatalogguard.js —— window.navigate/location 方法目录。
//
// 威胁模型：
//   window.navigate 与 document.location 赋 javascript: 协议等价于脚本执行，
//   导航值必须协议白名单。纯字符查表，不用正则。

const NMJ_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const NMJ_BLOCK = Object.freeze([
  'window.navigate',
  'document.location-javascript',
  'location.protocol-javascript',
  'navigate-input',
])

const NMJ_WARN = Object.freeze([
  'location.assign-unknown',
])

const NMJ_ALLOW = Object.freeze([
  'https-allowlist',
])

function NMJLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function NMJIn (list, v) {
  for (const x of list) { if (NMJLower(x) === v) return true }
  return false
}

function NMJClassify (tok) {
  const v = NMJLower(String(tok == null ? '' : tok).trim())
  if (NMJIn(NMJ_BLOCK, v)) return NMJ_CLASS.BLOCK
  if (NMJIn(NMJ_WARN, v)) return NMJ_CLASS.WARN
  if (NMJIn(NMJ_ALLOW, v)) return NMJ_CLASS.ALLOW
  return NMJ_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  NMJ_CLASS: NMJ_CLASS,
  NMJ_BLOCK: NMJ_BLOCK,
  NMJ_WARN: NMJ_WARN,
  NMJ_ALLOW: NMJ_ALLOW,
  NMJClassify: NMJClassify
})
