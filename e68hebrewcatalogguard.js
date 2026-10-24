'use strict'

// e68hebrewcatalogguard.js —— 希伯来文字码位目录。
//
// 威胁模型：
//   希伯来码位结合 RTL 双向字符可重排显示顺序，用于视觉欺骗与指令反转，
//   应配合双向控制剥离后再判定。纯字符查表，不用正则。

const E68R01_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R01_BLOCK = Object.freeze([
])

const E68R01_WARN = Object.freeze([
  'U+0590',
  'U+0591',
  'U+0592',
  'U+0593',
  'U+0594',
  'U+0595',
  'U+0596',
  'U+0597',
  'U+0598',
  'U+0599',
  'U+059A',
  'U+059B',
  'U+059C',
  'U+059D',
  'U+059E',
  'U+059F',
  'U+05A0',
  'U+05A1',
  'U+05A2',
  'U+05A3',
  'U+05A4',
  'U+05A5',
  'U+05A6',
  'U+05A7',
  'U+05A8',
  'U+05A9',
  'U+05AA',
  'U+05AB',
  'U+05AC',
  'U+05AD',
  'U+05AE',
  'U+05AF',
  'U+05B0',
  'U+05B1',
  'U+05B2',
  'U+05B3',
  'U+05B4',
  'U+05B5',
  'U+05B6',
  'U+05B7',
  'U+05B8',
  'U+05B9',
  'U+05BA',
  'U+05BB',
  'U+05BC',
  'U+05BD',
  'U+05BE',
  'U+05BF',
  'U+05C0',
  'U+05C1',
  'U+05C2',
  'U+05C3',
  'U+05C4',
  'U+05C5',
  'U+05C6',
  'U+05C7',
  'U+05C8',
  'U+05C9',
  'U+05CA',
  'U+05CB',
  'U+05CC',
  'U+05CD',
  'U+05CE',
  'U+05CF',
  'U+05D0',
  'U+05D1',
  'U+05D2',
  'U+05D3',
  'U+05D4',
  'U+05D5',
  'U+05D6',
  'U+05D7',
  'U+05D8',
  'U+05D9',
  'U+05DA',
  'U+05DB',
  'U+05DC',
  'U+05DD',
  'U+05DE',
  'U+05DF',
  'U+05E0',
  'U+05E1',
  'U+05E2',
  'U+05E3',
  'U+05E4',
  'U+05E5',
  'U+05E6',
  'U+05E7',
  'U+05E8',
  'U+05E9',
  'U+05EA',
  'U+05EB',
  'U+05EC',
  'U+05ED',
  'U+05EE',
  'U+05EF',
  'U+05F0',
  'U+05F1',
  'U+05F2',
  'U+05F3',
  'U+05F4',
  'U+05F5',
  'U+05F6',
  'U+05F7',
  'U+05F8',
  'U+05F9',
  'U+05FA',
  'U+05FB',
  'U+05FC',
  'U+05FD',
  'U+05FE',
  'U+05FF',
])

const E68R01_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R01Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R01In (list, v) {
  for (const x of list) { if (E68R01Lower(x) === v) return true }
  return false
}

function E68R01Classify (tok) {
  const v = E68R01Lower(String(tok == null ? '' : tok).trim())
  if (E68R01In(E68R01_BLOCK, v)) return E68R01_CLASS.BLOCK
  if (E68R01In(E68R01_WARN, v)) return E68R01_CLASS.WARN
  if (E68R01In(E68R01_ALLOW, v)) return E68R01_CLASS.ALLOW
  return E68R01_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R01_CLASS: E68R01_CLASS,
  E68R01_BLOCK: E68R01_BLOCK,
  E68R01_WARN: E68R01_WARN,
  E68R01_ALLOW: E68R01_ALLOW,
  E68R01Classify: E68R01Classify
})
