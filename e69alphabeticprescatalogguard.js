'use strict'

// e69alphabeticprescatalogguard.js —— 字母表示形式码位目录。
//
// 威胁模型：
//   ﬁ ﬂ 等连字在 NFKC 后展开为多字符 ASCII，规范化前后长度变化可绕过匹配，
//   应 NFKC 归一化。纯字符查表，不用正则。

const E69T33_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T33_BLOCK = Object.freeze([
])

const E69T33_WARN = Object.freeze([
  'U+FB00',
  'U+FB01',
  'U+FB02',
  'U+FB03',
  'U+FB04',
  'U+FB05',
  'U+FB06',
  'U+FB07',
  'U+FB08',
  'U+FB09',
  'U+FB0A',
  'U+FB0B',
  'U+FB0C',
  'U+FB0D',
  'U+FB0E',
  'U+FB0F',
  'U+FB10',
  'U+FB11',
  'U+FB12',
  'U+FB13',
  'U+FB14',
  'U+FB15',
  'U+FB16',
  'U+FB17',
  'U+FB18',
  'U+FB19',
  'U+FB1A',
  'U+FB1B',
  'U+FB1C',
  'U+FB1D',
  'U+FB1E',
  'U+FB1F',
  'U+FB20',
  'U+FB21',
  'U+FB22',
  'U+FB23',
  'U+FB24',
  'U+FB25',
  'U+FB26',
  'U+FB27',
  'U+FB28',
  'U+FB29',
  'U+FB2A',
  'U+FB2B',
  'U+FB2C',
  'U+FB2D',
  'U+FB2E',
  'U+FB2F',
  'U+FB30',
  'U+FB31',
  'U+FB32',
  'U+FB33',
  'U+FB34',
  'U+FB35',
  'U+FB36',
  'U+FB37',
  'U+FB38',
  'U+FB39',
  'U+FB3A',
  'U+FB3B',
  'U+FB3C',
  'U+FB3D',
  'U+FB3E',
  'U+FB3F',
  'U+FB40',
  'U+FB41',
  'U+FB42',
  'U+FB43',
  'U+FB44',
  'U+FB45',
  'U+FB46',
  'U+FB47',
  'U+FB48',
  'U+FB49',
  'U+FB4A',
  'U+FB4B',
  'U+FB4C',
  'U+FB4D',
  'U+FB4E',
  'U+FB4F',
])

const E69T33_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T33Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T33In (list, v) {
  for (const x of list) { if (E69T33Lower(x) === v) return true }
  return false
}

function E69T33Classify (tok) {
  const v = E69T33Lower(String(tok == null ? '' : tok))
  if (E69T33In(E69T33_BLOCK, v)) return E69T33_CLASS.BLOCK
  if (E69T33In(E69T33_WARN, v)) return E69T33_CLASS.WARN
  if (E69T33In(E69T33_ALLOW, v)) return E69T33_CLASS.ALLOW
  return E69T33_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T33_CLASS: E69T33_CLASS,
  E69T33_BLOCK: E69T33_BLOCK,
  E69T33_WARN: E69T33_WARN,
  E69T33_ALLOW: E69T33_ALLOW,
  E69T33Classify: E69T33Classify
})
