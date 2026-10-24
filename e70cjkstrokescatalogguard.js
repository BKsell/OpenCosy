'use strict'

// e70cjkstrokescatalogguard.js —— CJK 笔画码位目录。
//
// 威胁模型：
//   CJK 笔画字符在机器字段无正当用途，与部件形似可混淆匹配，
//   应直接拒绝。纯字符查表，不用正则。

const E70T56_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T56_BLOCK = Object.freeze([
  'U+31A0',
  'U+31A1',
  'U+31A2',
  'U+31A3',
  'U+31A4',
  'U+31A5',
  'U+31A6',
  'U+31A7',
  'U+31A8',
  'U+31A9',
  'U+31AA',
  'U+31AB',
  'U+31AC',
  'U+31AD',
  'U+31AE',
  'U+31AF',
  'U+31B0',
  'U+31B1',
  'U+31B2',
  'U+31B3',
  'U+31B4',
  'U+31B5',
  'U+31B6',
  'U+31B7',
  'U+31B8',
  'U+31B9',
  'U+31BA',
  'U+31BB',
  'U+31BC',
  'U+31BD',
  'U+31BE',
  'U+31BF',
])

const E70T56_WARN = Object.freeze([
])

const E70T56_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T56Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T56In (list, v) {
  for (const x of list) { if (E70T56Lower(x) === v) return true }
  return false
}

function E70T56Classify (tok) {
  const v = E70T56Lower(String(tok == null ? '' : tok))
  if (E70T56In(E70T56_BLOCK, v)) return E70T56_CLASS.BLOCK
  if (E70T56In(E70T56_WARN, v)) return E70T56_CLASS.WARN
  if (E70T56In(E70T56_ALLOW, v)) return E70T56_CLASS.ALLOW
  return E70T56_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T56_CLASS: E70T56_CLASS,
  E70T56_BLOCK: E70T56_BLOCK,
  E70T56_WARN: E70T56_WARN,
  E70T56_ALLOW: E70T56_ALLOW,
  E70T56Classify: E70T56Classify
})
