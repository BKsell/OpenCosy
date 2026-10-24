'use strict'

// e70ugariticcatalogguard.js —— 乌加里特楔形字母目录。
//
// 威胁模型：
//   乌加里特字母在常规字段无正当用途，缺字体时不可见，
//   应直接拒绝。纯字符查表，不用正则。

const E70U04_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U04_BLOCK = Object.freeze([
  'U+10380',
  'U+10381',
  'U+10382',
  'U+10383',
  'U+10384',
  'U+10385',
  'U+10386',
  'U+10387',
  'U+10388',
  'U+10389',
  'U+1038A',
  'U+1038B',
  'U+1038C',
  'U+1038D',
  'U+1038E',
  'U+1038F',
  'U+10390',
  'U+10391',
  'U+10392',
  'U+10393',
  'U+10394',
  'U+10395',
  'U+10396',
  'U+10397',
  'U+10398',
  'U+10399',
  'U+1039A',
  'U+1039B',
  'U+1039C',
  'U+1039D',
  'U+1039E',
  'U+1039F',
])

const E70U04_WARN = Object.freeze([
])

const E70U04_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U04Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U04In (list, v) {
  for (const x of list) { if (E70U04Lower(x) === v) return true }
  return false
}

function E70U04Classify (tok) {
  const v = E70U04Lower(String(tok == null ? '' : tok))
  if (E70U04In(E70U04_BLOCK, v)) return E70U04_CLASS.BLOCK
  if (E70U04In(E70U04_WARN, v)) return E70U04_CLASS.WARN
  if (E70U04In(E70U04_ALLOW, v)) return E70U04_CLASS.ALLOW
  return E70U04_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U04_CLASS: E70U04_CLASS,
  E70U04_BLOCK: E70U04_BLOCK,
  E70U04_WARN: E70U04_WARN,
  E70U04_ALLOW: E70U04_ALLOW,
  E70U04Classify: E70U04Classify
})
