'use strict'

// e70latinextccatalogguard.js —— 拉丁扩展 C 码位目录。
//
// 威胁模型：
//   拉丁扩展 C 中部分字母与 ASCII 近似，可用于同形混淆，
//   应 NFKC 归一化后判定。纯字符查表，不用正则。

const E70T52_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T52_BLOCK = Object.freeze([
])

const E70T52_WARN = Object.freeze([
  'U+2C60',
  'U+2C61',
  'U+2C62',
  'U+2C63',
  'U+2C64',
  'U+2C65',
  'U+2C66',
  'U+2C67',
  'U+2C68',
  'U+2C69',
  'U+2C6A',
  'U+2C6B',
  'U+2C6C',
  'U+2C6D',
  'U+2C6E',
  'U+2C6F',
  'U+2C70',
  'U+2C71',
  'U+2C72',
  'U+2C73',
  'U+2C74',
  'U+2C75',
  'U+2C76',
  'U+2C77',
  'U+2C78',
  'U+2C79',
  'U+2C7A',
  'U+2C7B',
  'U+2C7C',
  'U+2C7D',
  'U+2C7E',
  'U+2C7F',
])

const E70T52_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T52Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T52In (list, v) {
  for (const x of list) { if (E70T52Lower(x) === v) return true }
  return false
}

function E70T52Classify (tok) {
  const v = E70T52Lower(String(tok == null ? '' : tok))
  if (E70T52In(E70T52_BLOCK, v)) return E70T52_CLASS.BLOCK
  if (E70T52In(E70T52_WARN, v)) return E70T52_CLASS.WARN
  if (E70T52In(E70T52_ALLOW, v)) return E70T52_CLASS.ALLOW
  return E70T52_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T52_CLASS: E70T52_CLASS,
  E70T52_BLOCK: E70T52_BLOCK,
  E70T52_WARN: E70T52_WARN,
  E70T52_ALLOW: E70T52_ALLOW,
  E70T52Classify: E70T52Classify
})
