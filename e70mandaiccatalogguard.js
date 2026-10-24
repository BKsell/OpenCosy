'use strict'

// e70mandaiccatalogguard.js —— 曼达文字码位目录。
//
// 威胁模型：
//   曼达文字罕用且从右向左，可用于在字段中隐藏非预期内容，
//   应直接拒绝。纯字符查表，不用正则。

const E70T08_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T08_BLOCK = Object.freeze([
  'U+0840',
  'U+0841',
  'U+0842',
  'U+0843',
  'U+0844',
  'U+0845',
  'U+0846',
  'U+0847',
  'U+0848',
  'U+0849',
  'U+084A',
  'U+084B',
  'U+084C',
  'U+084D',
  'U+084E',
  'U+084F',
  'U+0850',
  'U+0851',
  'U+0852',
  'U+0853',
  'U+0854',
  'U+0855',
  'U+0856',
  'U+0857',
  'U+0858',
  'U+0859',
  'U+085A',
  'U+085B',
  'U+085C',
  'U+085D',
  'U+085E',
  'U+085F',
])

const E70T08_WARN = Object.freeze([
])

const E70T08_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T08Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T08In (list, v) {
  for (const x of list) { if (E70T08Lower(x) === v) return true }
  return false
}

function E70T08Classify (tok) {
  const v = E70T08Lower(String(tok == null ? '' : tok))
  if (E70T08In(E70T08_BLOCK, v)) return E70T08_CLASS.BLOCK
  if (E70T08In(E70T08_WARN, v)) return E70T08_CLASS.WARN
  if (E70T08In(E70T08_ALLOW, v)) return E70T08_CLASS.ALLOW
  return E70T08_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T08_CLASS: E70T08_CLASS,
  E70T08_BLOCK: E70T08_BLOCK,
  E70T08_WARN: E70T08_WARN,
  E70T08_ALLOW: E70T08_ALLOW,
  E70T08Classify: E70T08Classify
})
