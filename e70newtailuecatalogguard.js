'use strict'

// e70newtailuecatalogguard.js —— 新傣仂文字码位目录。
//
// 威胁模型：
//   新傣仂文罕用，在常规机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T27_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T27_BLOCK = Object.freeze([
  'U+1980',
  'U+1981',
  'U+1982',
  'U+1983',
  'U+1984',
  'U+1985',
  'U+1986',
  'U+1987',
  'U+1988',
  'U+1989',
  'U+198A',
  'U+198B',
  'U+198C',
  'U+198D',
  'U+198E',
  'U+198F',
  'U+1990',
  'U+1991',
  'U+1992',
  'U+1993',
  'U+1994',
  'U+1995',
  'U+1996',
  'U+1997',
  'U+1998',
  'U+1999',
  'U+199A',
  'U+199B',
  'U+199C',
  'U+199D',
  'U+199E',
  'U+199F',
  'U+19A0',
  'U+19A1',
  'U+19A2',
  'U+19A3',
  'U+19A4',
  'U+19A5',
  'U+19A6',
  'U+19A7',
  'U+19A8',
  'U+19A9',
  'U+19AA',
  'U+19AB',
  'U+19AC',
  'U+19AD',
  'U+19AE',
  'U+19AF',
  'U+19B0',
  'U+19B1',
  'U+19B2',
  'U+19B3',
  'U+19B4',
  'U+19B5',
  'U+19B6',
  'U+19B7',
  'U+19B8',
  'U+19B9',
  'U+19BA',
  'U+19BB',
  'U+19BC',
  'U+19BD',
  'U+19BE',
  'U+19BF',
  'U+19C0',
  'U+19C1',
  'U+19C2',
  'U+19C3',
  'U+19C4',
  'U+19C5',
  'U+19C6',
  'U+19C7',
  'U+19C8',
  'U+19C9',
  'U+19CA',
  'U+19CB',
  'U+19CC',
  'U+19CD',
  'U+19CE',
  'U+19CF',
  'U+19D0',
  'U+19D1',
  'U+19D2',
  'U+19D3',
  'U+19D4',
  'U+19D5',
  'U+19D6',
  'U+19D7',
  'U+19D8',
  'U+19D9',
  'U+19DA',
  'U+19DB',
  'U+19DC',
  'U+19DD',
  'U+19DE',
  'U+19DF',
])

const E70T27_WARN = Object.freeze([
])

const E70T27_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T27Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T27In (list, v) {
  for (const x of list) { if (E70T27Lower(x) === v) return true }
  return false
}

function E70T27Classify (tok) {
  const v = E70T27Lower(String(tok == null ? '' : tok))
  if (E70T27In(E70T27_BLOCK, v)) return E70T27_CLASS.BLOCK
  if (E70T27In(E70T27_WARN, v)) return E70T27_CLASS.WARN
  if (E70T27In(E70T27_ALLOW, v)) return E70T27_CLASS.ALLOW
  return E70T27_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T27_CLASS: E70T27_CLASS,
  E70T27_BLOCK: E70T27_BLOCK,
  E70T27_WARN: E70T27_WARN,
  E70T27_ALLOW: E70T27_ALLOW,
  E70T27Classify: E70T27Classify
})
