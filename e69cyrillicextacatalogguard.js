'use strict'

// e69cyrillicextacatalogguard.js —— 西里尔扩展 A 码位目录。
//
// 威胁模型：
//   扩展西里尔组合/修饰字符在常规字段无正当用途，可用于序列混淆，
//   应拒绝。纯字符查表，不用正则。

const E69T18_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T18_BLOCK = Object.freeze([
  'U+2DE0',
  'U+2DE1',
  'U+2DE2',
  'U+2DE3',
  'U+2DE4',
  'U+2DE5',
  'U+2DE6',
  'U+2DE7',
  'U+2DE8',
  'U+2DE9',
  'U+2DEA',
  'U+2DEB',
  'U+2DEC',
  'U+2DED',
  'U+2DEE',
  'U+2DEF',
  'U+2DF0',
  'U+2DF1',
  'U+2DF2',
  'U+2DF3',
  'U+2DF4',
  'U+2DF5',
  'U+2DF6',
  'U+2DF7',
  'U+2DF8',
  'U+2DF9',
  'U+2DFA',
  'U+2DFB',
  'U+2DFC',
  'U+2DFD',
  'U+2DFE',
  'U+2DFF',
])

const E69T18_WARN = Object.freeze([
])

const E69T18_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T18Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T18In (list, v) {
  for (const x of list) { if (E69T18Lower(x) === v) return true }
  return false
}

function E69T18Classify (tok) {
  const v = E69T18Lower(String(tok == null ? '' : tok))
  if (E69T18In(E69T18_BLOCK, v)) return E69T18_CLASS.BLOCK
  if (E69T18In(E69T18_WARN, v)) return E69T18_CLASS.WARN
  if (E69T18In(E69T18_ALLOW, v)) return E69T18_CLASS.ALLOW
  return E69T18_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T18_CLASS: E69T18_CLASS,
  E69T18_BLOCK: E69T18_BLOCK,
  E69T18_WARN: E69T18_WARN,
  E69T18_ALLOW: E69T18_ALLOW,
  E69T18Classify: E69T18Classify
})
