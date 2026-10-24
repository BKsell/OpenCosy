'use strict'

// e69olchikicatalogguard.js —— 奥尔奇基文字码位目录。
//
// 威胁模型：
//   奥尔奇基为小众文字，常规字段无正当用途，缺字体时无法稳定渲染，
//   应直接拒绝。纯字符查表，不用正则。

const E69T15_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T15_BLOCK = Object.freeze([
  'U+1C50',
  'U+1C51',
  'U+1C52',
  'U+1C53',
  'U+1C54',
  'U+1C55',
  'U+1C56',
  'U+1C57',
  'U+1C58',
  'U+1C59',
  'U+1C5A',
  'U+1C5B',
  'U+1C5C',
  'U+1C5D',
  'U+1C5E',
  'U+1C5F',
  'U+1C60',
  'U+1C61',
  'U+1C62',
  'U+1C63',
  'U+1C64',
  'U+1C65',
  'U+1C66',
  'U+1C67',
  'U+1C68',
  'U+1C69',
  'U+1C6A',
  'U+1C6B',
  'U+1C6C',
  'U+1C6D',
  'U+1C6E',
  'U+1C6F',
  'U+1C70',
  'U+1C71',
  'U+1C72',
  'U+1C73',
  'U+1C74',
  'U+1C75',
  'U+1C76',
  'U+1C77',
  'U+1C78',
  'U+1C79',
  'U+1C7A',
  'U+1C7B',
  'U+1C7C',
  'U+1C7D',
  'U+1C7E',
  'U+1C7F',
])

const E69T15_WARN = Object.freeze([
])

const E69T15_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T15Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T15In (list, v) {
  for (const x of list) { if (E69T15Lower(x) === v) return true }
  return false
}

function E69T15Classify (tok) {
  const v = E69T15Lower(String(tok == null ? '' : tok))
  if (E69T15In(E69T15_BLOCK, v)) return E69T15_CLASS.BLOCK
  if (E69T15In(E69T15_WARN, v)) return E69T15_CLASS.WARN
  if (E69T15In(E69T15_ALLOW, v)) return E69T15_CLASS.ALLOW
  return E69T15_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T15_CLASS: E69T15_CLASS,
  E69T15_BLOCK: E69T15_BLOCK,
  E69T15_WARN: E69T15_WARN,
  E69T15_ALLOW: E69T15_ALLOW,
  E69T15Classify: E69T15Classify
})
