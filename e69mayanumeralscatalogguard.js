'use strict'

// e69mayanumeralscatalogguard.js —— 玛雅数字符号码位目录。
//
// 威胁模型：
//   玛雅数字等罕用数字形式在常规字段无正当用途，缺字体时不可见，
//   机器字段应拒绝。纯字符查表，不用正则。

const E69U13_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69U13_BLOCK = Object.freeze([
  'U+1D2E0',
  'U+1D2E1',
  'U+1D2E2',
  'U+1D2E3',
  'U+1D2E4',
  'U+1D2E5',
  'U+1D2E6',
  'U+1D2E7',
  'U+1D2E8',
  'U+1D2E9',
  'U+1D2EA',
  'U+1D2EB',
  'U+1D2EC',
  'U+1D2ED',
  'U+1D2EE',
  'U+1D2EF',
  'U+1D2F0',
  'U+1D2F1',
  'U+1D2F2',
  'U+1D2F3',
  'U+1D2F4',
  'U+1D2F5',
  'U+1D2F6',
  'U+1D2F7',
  'U+1D2F8',
  'U+1D2F9',
  'U+1D2FA',
  'U+1D2FB',
  'U+1D2FC',
  'U+1D2FD',
  'U+1D2FE',
  'U+1D2FF',
])

const E69U13_WARN = Object.freeze([
])

const E69U13_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69U13Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69U13In (list, v) {
  for (const x of list) { if (E69U13Lower(x) === v) return true }
  return false
}

function E69U13Classify (tok) {
  const v = E69U13Lower(String(tok == null ? '' : tok))
  if (E69U13In(E69U13_BLOCK, v)) return E69U13_CLASS.BLOCK
  if (E69U13In(E69U13_WARN, v)) return E69U13_CLASS.WARN
  if (E69U13In(E69U13_ALLOW, v)) return E69U13_CLASS.ALLOW
  return E69U13_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69U13_CLASS: E69U13_CLASS,
  E69U13_BLOCK: E69U13_BLOCK,
  E69U13_WARN: E69U13_WARN,
  E69U13_ALLOW: E69U13_ALLOW,
  E69U13Classify: E69U13Classify
})
