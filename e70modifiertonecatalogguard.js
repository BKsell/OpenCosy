'use strict'

// e70modifiertonecatalogguard.js —— 修饰声调字母码位目录。
//
// 威胁模型：
//   声调修饰字母与普通字母视觉近似且不占组合位，可绕过字形检查，
//   应规范化后比较。纯字符查表，不用正则。

const E70T59_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T59_BLOCK = Object.freeze([
])

const E70T59_WARN = Object.freeze([
  'U+A700',
  'U+A701',
  'U+A702',
  'U+A703',
  'U+A704',
  'U+A705',
  'U+A706',
  'U+A707',
  'U+A708',
  'U+A709',
  'U+A70A',
  'U+A70B',
  'U+A70C',
  'U+A70D',
  'U+A70E',
  'U+A70F',
  'U+A710',
  'U+A711',
  'U+A712',
  'U+A713',
  'U+A714',
  'U+A715',
  'U+A716',
  'U+A717',
  'U+A718',
  'U+A719',
  'U+A71A',
  'U+A71B',
  'U+A71C',
  'U+A71D',
  'U+A71E',
  'U+A71F',
])

const E70T59_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T59Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T59In (list, v) {
  for (const x of list) { if (E70T59Lower(x) === v) return true }
  return false
}

function E70T59Classify (tok) {
  const v = E70T59Lower(String(tok == null ? '' : tok))
  if (E70T59In(E70T59_BLOCK, v)) return E70T59_CLASS.BLOCK
  if (E70T59In(E70T59_WARN, v)) return E70T59_CLASS.WARN
  if (E70T59In(E70T59_ALLOW, v)) return E70T59_CLASS.ALLOW
  return E70T59_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T59_CLASS: E70T59_CLASS,
  E70T59_BLOCK: E70T59_BLOCK,
  E70T59_WARN: E70T59_WARN,
  E70T59_ALLOW: E70T59_ALLOW,
  E70T59Classify: E70T59Classify
})
