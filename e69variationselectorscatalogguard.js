'use strict'

// e69variationselectorscatalogguard.js —— 变体选择符码位目录。
//
// 威胁模型：
//   VS1-VS16 本身不可见却改变前一字符的字形选择，可让同一码点序列渲染成不同符号，
//   机器字段应拒绝。纯字符查表，不用正则。

const E69T40_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T40_BLOCK = Object.freeze([
  'U+FE00',
  'U+FE01',
  'U+FE02',
  'U+FE03',
  'U+FE04',
  'U+FE05',
  'U+FE06',
  'U+FE07',
  'U+FE08',
  'U+FE09',
  'U+FE0A',
  'U+FE0B',
  'U+FE0C',
  'U+FE0D',
  'U+FE0E',
  'U+FE0F',
])

const E69T40_WARN = Object.freeze([
])

const E69T40_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T40Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T40In (list, v) {
  for (const x of list) { if (E69T40Lower(x) === v) return true }
  return false
}

function E69T40Classify (tok) {
  const v = E69T40Lower(String(tok == null ? '' : tok))
  if (E69T40In(E69T40_BLOCK, v)) return E69T40_CLASS.BLOCK
  if (E69T40In(E69T40_WARN, v)) return E69T40_CLASS.WARN
  if (E69T40In(E69T40_ALLOW, v)) return E69T40_CLASS.ALLOW
  return E69T40_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T40_CLASS: E69T40_CLASS,
  E69T40_BLOCK: E69T40_BLOCK,
  E69T40_WARN: E69T40_WARN,
  E69T40_ALLOW: E69T40_ALLOW,
  E69T40Classify: E69T40Classify
})
