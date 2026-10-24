'use strict'

// e70thaanacatalogguard.js —— 它拿文字码位目录。
//
// 威胁模型：
//   它拿文字方向与渲染依赖字体，在标识符/路径中无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T05_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T05_BLOCK = Object.freeze([
  'U+0780',
  'U+0781',
  'U+0782',
  'U+0783',
  'U+0784',
  'U+0785',
  'U+0786',
  'U+0787',
  'U+0788',
  'U+0789',
  'U+078A',
  'U+078B',
  'U+078C',
  'U+078D',
  'U+078E',
  'U+078F',
  'U+0790',
  'U+0791',
  'U+0792',
  'U+0793',
  'U+0794',
  'U+0795',
  'U+0796',
  'U+0797',
  'U+0798',
  'U+0799',
  'U+079A',
  'U+079B',
  'U+079C',
  'U+079D',
  'U+079E',
  'U+079F',
  'U+07A0',
  'U+07A1',
  'U+07A2',
  'U+07A3',
  'U+07A4',
  'U+07A5',
  'U+07A6',
  'U+07A7',
  'U+07A8',
  'U+07A9',
  'U+07AA',
  'U+07AB',
  'U+07AC',
  'U+07AD',
  'U+07AE',
  'U+07AF',
  'U+07B0',
  'U+07B1',
  'U+07B2',
  'U+07B3',
  'U+07B4',
  'U+07B5',
  'U+07B6',
  'U+07B7',
  'U+07B8',
  'U+07B9',
  'U+07BA',
  'U+07BB',
  'U+07BC',
  'U+07BD',
  'U+07BE',
  'U+07BF',
])

const E70T05_WARN = Object.freeze([
])

const E70T05_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T05Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T05In (list, v) {
  for (const x of list) { if (E70T05Lower(x) === v) return true }
  return false
}

function E70T05Classify (tok) {
  const v = E70T05Lower(String(tok == null ? '' : tok))
  if (E70T05In(E70T05_BLOCK, v)) return E70T05_CLASS.BLOCK
  if (E70T05In(E70T05_WARN, v)) return E70T05_CLASS.WARN
  if (E70T05In(E70T05_ALLOW, v)) return E70T05_CLASS.ALLOW
  return E70T05_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T05_CLASS: E70T05_CLASS,
  E70T05_BLOCK: E70T05_BLOCK,
  E70T05_WARN: E70T05_WARN,
  E70T05_ALLOW: E70T05_ALLOW,
  E70T05Classify: E70T05Classify
})
