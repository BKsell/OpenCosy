'use strict'

// e69phoeniciancatalogguard.js —— 腓尼基文字码位目录。
//
// 威胁模型：
//   腓尼基字母在常规机器字段无正当用途，缺字体时不可见，
//   应拒绝。纯字符查表，不用正则。

const E69T42_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T42_BLOCK = Object.freeze([
  'U+10900',
  'U+10901',
  'U+10902',
  'U+10903',
  'U+10904',
  'U+10905',
  'U+10906',
  'U+10907',
  'U+10908',
  'U+10909',
  'U+1090A',
  'U+1090B',
  'U+1090C',
  'U+1090D',
  'U+1090E',
  'U+1090F',
  'U+10910',
  'U+10911',
  'U+10912',
  'U+10913',
  'U+10914',
  'U+10915',
  'U+10916',
  'U+10917',
  'U+10918',
  'U+10919',
  'U+1091A',
  'U+1091B',
  'U+1091C',
  'U+1091D',
  'U+1091E',
  'U+1091F',
])

const E69T42_WARN = Object.freeze([
])

const E69T42_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T42Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T42In (list, v) {
  for (const x of list) { if (E69T42Lower(x) === v) return true }
  return false
}

function E69T42Classify (tok) {
  const v = E69T42Lower(String(tok == null ? '' : tok))
  if (E69T42In(E69T42_BLOCK, v)) return E69T42_CLASS.BLOCK
  if (E69T42In(E69T42_WARN, v)) return E69T42_CLASS.WARN
  if (E69T42In(E69T42_ALLOW, v)) return E69T42_CLASS.ALLOW
  return E69T42_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T42_CLASS: E69T42_CLASS,
  E69T42_BLOCK: E69T42_BLOCK,
  E69T42_WARN: E69T42_WARN,
  E69T42_ALLOW: E69T42_ALLOW,
  E69T42Classify: E69T42Classify
})
