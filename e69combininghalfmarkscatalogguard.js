'use strict'

// e69combininghalfmarkscatalogguard.js —— 组合半记号码位目录。
//
// 威胁模型：
//   组合半记号用于连字连接控制，常规字段无正当用途，可改变断字结果，
//   应拒绝。纯字符查表，不用正则。

const E69T39_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T39_BLOCK = Object.freeze([
  'U+FE20',
  'U+FE21',
  'U+FE22',
  'U+FE23',
  'U+FE24',
  'U+FE25',
  'U+FE26',
  'U+FE27',
  'U+FE28',
  'U+FE29',
  'U+FE2A',
  'U+FE2B',
  'U+FE2C',
  'U+FE2D',
  'U+FE2E',
  'U+FE2F',
])

const E69T39_WARN = Object.freeze([
])

const E69T39_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T39Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T39In (list, v) {
  for (const x of list) { if (E69T39Lower(x) === v) return true }
  return false
}

function E69T39Classify (tok) {
  const v = E69T39Lower(String(tok == null ? '' : tok))
  if (E69T39In(E69T39_BLOCK, v)) return E69T39_CLASS.BLOCK
  if (E69T39In(E69T39_WARN, v)) return E69T39_CLASS.WARN
  if (E69T39In(E69T39_ALLOW, v)) return E69T39_CLASS.ALLOW
  return E69T39_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T39_CLASS: E69T39_CLASS,
  E69T39_BLOCK: E69T39_BLOCK,
  E69T39_WARN: E69T39_WARN,
  E69T39_ALLOW: E69T39_ALLOW,
  E69T39Classify: E69T39Classify
})
