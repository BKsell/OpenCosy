'use strict'

// e69tifinaghcatalogguard.js —— 提非纳文字码位目录。
//
// 威胁模型：
//   提非纳文字罕用且渲染不一致，可在标识符中隐藏非 ASCII 数据，
//   应直接拒绝。纯字符查表，不用正则。

const E69T17_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T17_BLOCK = Object.freeze([
  'U+2D30',
  'U+2D31',
  'U+2D32',
  'U+2D33',
  'U+2D34',
  'U+2D35',
  'U+2D36',
  'U+2D37',
  'U+2D38',
  'U+2D39',
  'U+2D3A',
  'U+2D3B',
  'U+2D3C',
  'U+2D3D',
  'U+2D3E',
  'U+2D3F',
  'U+2D40',
  'U+2D41',
  'U+2D42',
  'U+2D43',
  'U+2D44',
  'U+2D45',
  'U+2D46',
  'U+2D47',
  'U+2D48',
  'U+2D49',
  'U+2D4A',
  'U+2D4B',
  'U+2D4C',
  'U+2D4D',
  'U+2D4E',
  'U+2D4F',
  'U+2D50',
  'U+2D51',
  'U+2D52',
  'U+2D53',
  'U+2D54',
  'U+2D55',
  'U+2D56',
  'U+2D57',
  'U+2D58',
  'U+2D59',
  'U+2D5A',
  'U+2D5B',
  'U+2D5C',
  'U+2D5D',
  'U+2D5E',
  'U+2D5F',
  'U+2D60',
  'U+2D61',
  'U+2D62',
  'U+2D63',
  'U+2D64',
  'U+2D65',
  'U+2D66',
  'U+2D67',
  'U+2D68',
  'U+2D69',
  'U+2D6A',
  'U+2D6B',
  'U+2D6C',
  'U+2D6D',
  'U+2D6E',
  'U+2D6F',
  'U+2D70',
  'U+2D71',
  'U+2D72',
  'U+2D73',
  'U+2D74',
  'U+2D75',
  'U+2D76',
  'U+2D77',
  'U+2D78',
  'U+2D79',
  'U+2D7A',
  'U+2D7B',
  'U+2D7C',
  'U+2D7D',
  'U+2D7E',
  'U+2D7F',
])

const E69T17_WARN = Object.freeze([
])

const E69T17_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T17Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T17In (list, v) {
  for (const x of list) { if (E69T17Lower(x) === v) return true }
  return false
}

function E69T17Classify (tok) {
  const v = E69T17Lower(String(tok == null ? '' : tok))
  if (E69T17In(E69T17_BLOCK, v)) return E69T17_CLASS.BLOCK
  if (E69T17In(E69T17_WARN, v)) return E69T17_CLASS.WARN
  if (E69T17In(E69T17_ALLOW, v)) return E69T17_CLASS.ALLOW
  return E69T17_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T17_CLASS: E69T17_CLASS,
  E69T17_BLOCK: E69T17_BLOCK,
  E69T17_WARN: E69T17_WARN,
  E69T17_ALLOW: E69T17_ALLOW,
  E69T17Classify: E69T17Classify
})
