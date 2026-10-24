'use strict'

// e70bengalicatalogguard.js —— 孟加拉文字码位目录。
//
// 威胁模型：
//   孟加拉文字符含组合与连写，在机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T10_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T10_BLOCK = Object.freeze([
  'U+0980',
  'U+0981',
  'U+0982',
  'U+0983',
  'U+0984',
  'U+0985',
  'U+0986',
  'U+0987',
  'U+0988',
  'U+0989',
  'U+098A',
  'U+098B',
  'U+098C',
  'U+098D',
  'U+098E',
  'U+098F',
  'U+0990',
  'U+0991',
  'U+0992',
  'U+0993',
  'U+0994',
  'U+0995',
  'U+0996',
  'U+0997',
  'U+0998',
  'U+0999',
  'U+099A',
  'U+099B',
  'U+099C',
  'U+099D',
  'U+099E',
  'U+099F',
  'U+09A0',
  'U+09A1',
  'U+09A2',
  'U+09A3',
  'U+09A4',
  'U+09A5',
  'U+09A6',
  'U+09A7',
  'U+09A8',
  'U+09A9',
  'U+09AA',
  'U+09AB',
  'U+09AC',
  'U+09AD',
  'U+09AE',
  'U+09AF',
  'U+09B0',
  'U+09B1',
  'U+09B2',
  'U+09B3',
  'U+09B4',
  'U+09B5',
  'U+09B6',
  'U+09B7',
  'U+09B8',
  'U+09B9',
  'U+09BA',
  'U+09BB',
  'U+09BC',
  'U+09BD',
  'U+09BE',
  'U+09BF',
  'U+09C0',
  'U+09C1',
  'U+09C2',
  'U+09C3',
  'U+09C4',
  'U+09C5',
  'U+09C6',
  'U+09C7',
  'U+09C8',
  'U+09C9',
  'U+09CA',
  'U+09CB',
  'U+09CC',
  'U+09CD',
  'U+09CE',
  'U+09CF',
  'U+09D0',
  'U+09D1',
  'U+09D2',
  'U+09D3',
  'U+09D4',
  'U+09D5',
  'U+09D6',
  'U+09D7',
  'U+09D8',
  'U+09D9',
  'U+09DA',
  'U+09DB',
  'U+09DC',
  'U+09DD',
  'U+09DE',
  'U+09DF',
  'U+09E0',
  'U+09E1',
  'U+09E2',
  'U+09E3',
  'U+09E4',
  'U+09E5',
  'U+09E6',
  'U+09E7',
  'U+09E8',
  'U+09E9',
  'U+09EA',
  'U+09EB',
  'U+09EC',
  'U+09ED',
  'U+09EE',
  'U+09EF',
  'U+09F0',
  'U+09F1',
  'U+09F2',
  'U+09F3',
  'U+09F4',
  'U+09F5',
  'U+09F6',
  'U+09F7',
  'U+09F8',
  'U+09F9',
  'U+09FA',
  'U+09FB',
  'U+09FC',
  'U+09FD',
  'U+09FE',
  'U+09FF',
])

const E70T10_WARN = Object.freeze([
])

const E70T10_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T10Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T10In (list, v) {
  for (const x of list) { if (E70T10Lower(x) === v) return true }
  return false
}

function E70T10Classify (tok) {
  const v = E70T10Lower(String(tok == null ? '' : tok))
  if (E70T10In(E70T10_BLOCK, v)) return E70T10_CLASS.BLOCK
  if (E70T10In(E70T10_WARN, v)) return E70T10_CLASS.WARN
  if (E70T10In(E70T10_ALLOW, v)) return E70T10_CLASS.ALLOW
  return E70T10_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T10_CLASS: E70T10_CLASS,
  E70T10_BLOCK: E70T10_BLOCK,
  E70T10_WARN: E70T10_WARN,
  E70T10_ALLOW: E70T10_ALLOW,
  E70T10Classify: E70T10Classify
})
