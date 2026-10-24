'use strict'

// e69supersubscriptcatalogguard.js —— 上下标符号码位目录。
//
// 威胁模型：
//   上标/下标数字与字母与 ASCII 基字符同形，可绕过字母数字匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const E69T22_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T22_BLOCK = Object.freeze([
])

const E69T22_WARN = Object.freeze([
  'U+2070',
  'U+2071',
  'U+2072',
  'U+2073',
  'U+2074',
  'U+2075',
  'U+2076',
  'U+2077',
  'U+2078',
  'U+2079',
  'U+207A',
  'U+207B',
  'U+207C',
  'U+207D',
  'U+207E',
  'U+207F',
  'U+2080',
  'U+2081',
  'U+2082',
  'U+2083',
  'U+2084',
  'U+2085',
  'U+2086',
  'U+2087',
  'U+2088',
  'U+2089',
  'U+208A',
  'U+208B',
  'U+208C',
  'U+208D',
  'U+208E',
  'U+208F',
  'U+2090',
  'U+2091',
  'U+2092',
  'U+2093',
  'U+2094',
  'U+2095',
  'U+2096',
  'U+2097',
  'U+2098',
  'U+2099',
  'U+209A',
  'U+209B',
  'U+209C',
  'U+209D',
  'U+209E',
  'U+209F',
])

const E69T22_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T22Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T22In (list, v) {
  for (const x of list) { if (E69T22Lower(x) === v) return true }
  return false
}

function E69T22Classify (tok) {
  const v = E69T22Lower(String(tok == null ? '' : tok))
  if (E69T22In(E69T22_BLOCK, v)) return E69T22_CLASS.BLOCK
  if (E69T22In(E69T22_WARN, v)) return E69T22_CLASS.WARN
  if (E69T22In(E69T22_ALLOW, v)) return E69T22_CLASS.ALLOW
  return E69T22_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T22_CLASS: E69T22_CLASS,
  E69T22_BLOCK: E69T22_BLOCK,
  E69T22_WARN: E69T22_WARN,
  E69T22_ALLOW: E69T22_ALLOW,
  E69T22Classify: E69T22Classify
})
