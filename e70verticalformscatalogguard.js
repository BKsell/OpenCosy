'use strict'

// e70verticalformscatalogguard.js —— 竖排形式标点码位目录。
//
// 威胁模型：
//   竖排形式标点与常规标点对应但码点不同，可替换分隔符绕过匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const E70T60_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T60_BLOCK = Object.freeze([
])

const E70T60_WARN = Object.freeze([
  'U+FE10',
  'U+FE11',
  'U+FE12',
  'U+FE13',
  'U+FE14',
  'U+FE15',
  'U+FE16',
  'U+FE17',
  'U+FE18',
  'U+FE19',
  'U+FE1A',
  'U+FE1B',
  'U+FE1C',
  'U+FE1D',
  'U+FE1E',
  'U+FE1F',
])

const E70T60_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T60Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T60In (list, v) {
  for (const x of list) { if (E70T60Lower(x) === v) return true }
  return false
}

function E70T60Classify (tok) {
  const v = E70T60Lower(String(tok == null ? '' : tok))
  if (E70T60In(E70T60_BLOCK, v)) return E70T60_CLASS.BLOCK
  if (E70T60In(E70T60_WARN, v)) return E70T60_CLASS.WARN
  if (E70T60In(E70T60_ALLOW, v)) return E70T60_CLASS.ALLOW
  return E70T60_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T60_CLASS: E70T60_CLASS,
  E70T60_BLOCK: E70T60_BLOCK,
  E70T60_WARN: E70T60_WARN,
  E70T60_ALLOW: E70T60_ALLOW,
  E70T60Classify: E70T60Classify
})
