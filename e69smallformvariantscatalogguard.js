'use strict'

// e69smallformvariantscatalogguard.js —— 小型形式变体标点码位目录。
//
// 威胁模型：
//   ﹨ ﹤ ﹥ 等小型标点与 ASCII 反斜杠/尖括号视觉近似，是路径与标签混淆来源，
//   应 NFKC 归一化。纯字符查表，不用正则。

const E69T34_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T34_BLOCK = Object.freeze([
])

const E69T34_WARN = Object.freeze([
  'U+FE50',
  'U+FE51',
  'U+FE52',
  'U+FE53',
  'U+FE54',
  'U+FE55',
  'U+FE56',
  'U+FE57',
  'U+FE58',
  'U+FE59',
  'U+FE5A',
  'U+FE5B',
  'U+FE5C',
  'U+FE5D',
  'U+FE5E',
  'U+FE5F',
  'U+FE60',
  'U+FE61',
  'U+FE62',
  'U+FE63',
  'U+FE64',
  'U+FE65',
  'U+FE66',
  'U+FE67',
  'U+FE68',
  'U+FE69',
  'U+FE6A',
  'U+FE6B',
  'U+FE6C',
  'U+FE6D',
  'U+FE6E',
  'U+FE6F',
])

const E69T34_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T34Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T34In (list, v) {
  for (const x of list) { if (E69T34Lower(x) === v) return true }
  return false
}

function E69T34Classify (tok) {
  const v = E69T34Lower(String(tok == null ? '' : tok))
  if (E69T34In(E69T34_BLOCK, v)) return E69T34_CLASS.BLOCK
  if (E69T34In(E69T34_WARN, v)) return E69T34_CLASS.WARN
  if (E69T34In(E69T34_ALLOW, v)) return E69T34_CLASS.ALLOW
  return E69T34_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T34_CLASS: E69T34_CLASS,
  E69T34_BLOCK: E69T34_BLOCK,
  E69T34_WARN: E69T34_WARN,
  E69T34_ALLOW: E69T34_ALLOW,
  E69T34Classify: E69T34Classify
})
