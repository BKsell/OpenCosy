'use strict'

// e68nkocatalogguard.js —— NKo 文字码位目录。
//
// 威胁模型：
//   NKo 等罕用文字块在多数环境缺字体而无法稳定渲染，可承载不可见载荷，
//   标识符/路径中应直接拒绝。纯字符查表，不用正则。

const E68R04_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R04_BLOCK = Object.freeze([
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

const E68R04_WARN = Object.freeze([
])

const E68R04_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R04Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R04In (list, v) {
  for (const x of list) { if (E68R04Lower(x) === v) return true }
  return false
}

function E68R04Classify (tok) {
  const v = E68R04Lower(String(tok == null ? '' : tok).trim())
  if (E68R04In(E68R04_BLOCK, v)) return E68R04_CLASS.BLOCK
  if (E68R04In(E68R04_WARN, v)) return E68R04_CLASS.WARN
  if (E68R04In(E68R04_ALLOW, v)) return E68R04_CLASS.ALLOW
  return E68R04_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R04_CLASS: E68R04_CLASS,
  E68R04_BLOCK: E68R04_BLOCK,
  E68R04_WARN: E68R04_WARN,
  E68R04_ALLOW: E68R04_ALLOW,
  E68R04Classify: E68R04Classify
})
