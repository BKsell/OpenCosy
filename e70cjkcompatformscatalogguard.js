'use strict'

// e70cjkcompatformscatalogguard.js —— CJK 兼容形式标点码位目录。
//
// 威胁模型：
//   ︰ ﹏ 等兼容形式标点与 ASCII/常规标点视觉近似，可仿冒分隔符，
//   应 NFKC 归一化后判定。纯字符查表，不用正则。

const E70T61_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T61_BLOCK = Object.freeze([
])

const E70T61_WARN = Object.freeze([
  'U+FE30',
  'U+FE31',
  'U+FE32',
  'U+FE33',
  'U+FE34',
  'U+FE35',
  'U+FE36',
  'U+FE37',
  'U+FE38',
  'U+FE39',
  'U+FE3A',
  'U+FE3B',
  'U+FE3C',
  'U+FE3D',
  'U+FE3E',
  'U+FE3F',
  'U+FE40',
  'U+FE41',
  'U+FE42',
  'U+FE43',
  'U+FE44',
  'U+FE45',
  'U+FE46',
  'U+FE47',
  'U+FE48',
  'U+FE49',
  'U+FE4A',
  'U+FE4B',
  'U+FE4C',
  'U+FE4D',
  'U+FE4E',
  'U+FE4F',
])

const E70T61_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T61Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T61In (list, v) {
  for (const x of list) { if (E70T61Lower(x) === v) return true }
  return false
}

function E70T61Classify (tok) {
  const v = E70T61Lower(String(tok == null ? '' : tok))
  if (E70T61In(E70T61_BLOCK, v)) return E70T61_CLASS.BLOCK
  if (E70T61In(E70T61_WARN, v)) return E70T61_CLASS.WARN
  if (E70T61In(E70T61_ALLOW, v)) return E70T61_CLASS.ALLOW
  return E70T61_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T61_CLASS: E70T61_CLASS,
  E70T61_BLOCK: E70T61_BLOCK,
  E70T61_WARN: E70T61_WARN,
  E70T61_ALLOW: E70T61_ALLOW,
  E70T61Classify: E70T61Classify
})
