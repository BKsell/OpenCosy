'use strict'

// e69cyrillicsuppcatalogguard.js —— 西里尔文字补充码位目录。
//
// 威胁模型：
//   补充西里尔字母同样存在与拉丁混排的同形风险，
//   应规范化后比较。纯字符查表，不用正则。

const E69T08_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T08_BLOCK = Object.freeze([
])

const E69T08_WARN = Object.freeze([
  'U+0500',
  'U+0501',
  'U+0502',
  'U+0503',
  'U+0504',
  'U+0505',
  'U+0506',
  'U+0507',
  'U+0508',
  'U+0509',
  'U+050A',
  'U+050B',
  'U+050C',
  'U+050D',
  'U+050E',
  'U+050F',
  'U+0510',
  'U+0511',
  'U+0512',
  'U+0513',
  'U+0514',
  'U+0515',
  'U+0516',
  'U+0517',
  'U+0518',
  'U+0519',
  'U+051A',
  'U+051B',
  'U+051C',
  'U+051D',
  'U+051E',
  'U+051F',
  'U+0520',
  'U+0521',
  'U+0522',
  'U+0523',
  'U+0524',
  'U+0525',
  'U+0526',
  'U+0527',
  'U+0528',
  'U+0529',
  'U+052A',
  'U+052B',
  'U+052C',
  'U+052D',
  'U+052E',
  'U+052F',
])

const E69T08_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T08Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T08In (list, v) {
  for (const x of list) { if (E69T08Lower(x) === v) return true }
  return false
}

function E69T08Classify (tok) {
  const v = E69T08Lower(String(tok == null ? '' : tok))
  if (E69T08In(E69T08_BLOCK, v)) return E69T08_CLASS.BLOCK
  if (E69T08In(E69T08_WARN, v)) return E69T08_CLASS.WARN
  if (E69T08In(E69T08_ALLOW, v)) return E69T08_CLASS.ALLOW
  return E69T08_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T08_CLASS: E69T08_CLASS,
  E69T08_BLOCK: E69T08_BLOCK,
  E69T08_WARN: E69T08_WARN,
  E69T08_ALLOW: E69T08_ALLOW,
  E69T08Classify: E69T08Classify
})
