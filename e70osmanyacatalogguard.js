'use strict'

// e70osmanyacatalogguard.js —— 奥斯曼亚字母平面目录。
//
// 威胁模型：
//   奥斯曼亚字母罕用、渲染依赖字体，可隐藏载荷，
//   应直接拒绝。纯字符查表，不用正则。

const E70U07_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70U07_BLOCK = Object.freeze([
  'U+10480',
  'U+10481',
  'U+10482',
  'U+10483',
  'U+10484',
  'U+10485',
  'U+10486',
  'U+10487',
  'U+10488',
  'U+10489',
  'U+1048A',
  'U+1048B',
  'U+1048C',
  'U+1048D',
  'U+1048E',
  'U+1048F',
  'U+10490',
  'U+10491',
  'U+10492',
  'U+10493',
  'U+10494',
  'U+10495',
  'U+10496',
  'U+10497',
  'U+10498',
  'U+10499',
  'U+1049A',
  'U+1049B',
  'U+1049C',
  'U+1049D',
  'U+1049E',
  'U+1049F',
  'U+104A0',
  'U+104A1',
  'U+104A2',
  'U+104A3',
  'U+104A4',
  'U+104A5',
  'U+104A6',
  'U+104A7',
  'U+104A8',
  'U+104A9',
  'U+104AA',
  'U+104AB',
  'U+104AC',
  'U+104AD',
  'U+104AE',
  'U+104AF',
])

const E70U07_WARN = Object.freeze([
])

const E70U07_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70U07Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70U07In (list, v) {
  for (const x of list) { if (E70U07Lower(x) === v) return true }
  return false
}

function E70U07Classify (tok) {
  const v = E70U07Lower(String(tok == null ? '' : tok))
  if (E70U07In(E70U07_BLOCK, v)) return E70U07_CLASS.BLOCK
  if (E70U07In(E70U07_WARN, v)) return E70U07_CLASS.WARN
  if (E70U07In(E70U07_ALLOW, v)) return E70U07_CLASS.ALLOW
  return E70U07_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70U07_CLASS: E70U07_CLASS,
  E70U07_BLOCK: E70U07_BLOCK,
  E70U07_WARN: E70U07_WARN,
  E70U07_ALLOW: E70U07_ALLOW,
  E70U07Classify: E70U07Classify
})
