'use strict'

// e70nkocatalogguard.js —— 西非书面文字码位目录。
//
// 威胁模型：
//   NKo 文字在常规字段无正当用途且含组合记号，可隐藏数据，
//   应直接拒绝。纯字符查表，不用正则。

const E70T06_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T06_BLOCK = Object.freeze([
  'U+07C0',
  'U+07C1',
  'U+07C2',
  'U+07C3',
  'U+07C4',
  'U+07C5',
  'U+07C6',
  'U+07C7',
  'U+07C8',
  'U+07C9',
  'U+07CA',
  'U+07CB',
  'U+07CC',
  'U+07CD',
  'U+07CE',
  'U+07CF',
  'U+07D0',
  'U+07D1',
  'U+07D2',
  'U+07D3',
  'U+07D4',
  'U+07D5',
  'U+07D6',
  'U+07D7',
  'U+07D8',
  'U+07D9',
  'U+07DA',
  'U+07DB',
  'U+07DC',
  'U+07DD',
  'U+07DE',
  'U+07DF',
  'U+07E0',
  'U+07E1',
  'U+07E2',
  'U+07E3',
  'U+07E4',
  'U+07E5',
  'U+07E6',
  'U+07E7',
  'U+07E8',
  'U+07E9',
  'U+07EA',
  'U+07EB',
  'U+07EC',
  'U+07ED',
  'U+07EE',
  'U+07EF',
  'U+07F0',
  'U+07F1',
  'U+07F2',
  'U+07F3',
  'U+07F4',
  'U+07F5',
  'U+07F6',
  'U+07F7',
  'U+07F8',
  'U+07F9',
  'U+07FA',
  'U+07FB',
  'U+07FC',
  'U+07FD',
  'U+07FE',
  'U+07FF',
])

const E70T06_WARN = Object.freeze([
])

const E70T06_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T06Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T06In (list, v) {
  for (const x of list) { if (E70T06Lower(x) === v) return true }
  return false
}

function E70T06Classify (tok) {
  const v = E70T06Lower(String(tok == null ? '' : tok))
  if (E70T06In(E70T06_BLOCK, v)) return E70T06_CLASS.BLOCK
  if (E70T06In(E70T06_WARN, v)) return E70T06_CLASS.WARN
  if (E70T06In(E70T06_ALLOW, v)) return E70T06_CLASS.ALLOW
  return E70T06_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T06_CLASS: E70T06_CLASS,
  E70T06_BLOCK: E70T06_BLOCK,
  E70T06_WARN: E70T06_WARN,
  E70T06_ALLOW: E70T06_ALLOW,
  E70T06Classify: E70T06Classify
})
