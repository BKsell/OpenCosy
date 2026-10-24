'use strict'

// e68georgiancatalogguard.js —— 格鲁吉亚文字码位目录。
//
// 威胁模型：
//   格鲁吉亚 Mtavruli 与 Asomtavruli 存在大小写式同形，
//   标识符比较应规范化。纯字符查表，不用正则。

const E68R19_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R19_BLOCK = Object.freeze([
])

const E68R19_WARN = Object.freeze([
  'U+10A0',
  'U+10A1',
  'U+10A2',
  'U+10A3',
  'U+10A4',
  'U+10A5',
  'U+10A6',
  'U+10A7',
  'U+10A8',
  'U+10A9',
  'U+10AA',
  'U+10AB',
  'U+10AC',
  'U+10AD',
  'U+10AE',
  'U+10AF',
  'U+10B0',
  'U+10B1',
  'U+10B2',
  'U+10B3',
  'U+10B4',
  'U+10B5',
  'U+10B6',
  'U+10B7',
  'U+10B8',
  'U+10B9',
  'U+10BA',
  'U+10BB',
  'U+10BC',
  'U+10BD',
  'U+10BE',
  'U+10BF',
  'U+10C0',
  'U+10C1',
  'U+10C2',
  'U+10C3',
  'U+10C4',
  'U+10C5',
  'U+10C6',
  'U+10C7',
  'U+10C8',
  'U+10C9',
  'U+10CA',
  'U+10CB',
  'U+10CC',
  'U+10CD',
  'U+10CE',
  'U+10CF',
  'U+10D0',
  'U+10D1',
  'U+10D2',
  'U+10D3',
  'U+10D4',
  'U+10D5',
  'U+10D6',
  'U+10D7',
  'U+10D8',
  'U+10D9',
  'U+10DA',
  'U+10DB',
  'U+10DC',
  'U+10DD',
  'U+10DE',
  'U+10DF',
  'U+10E0',
  'U+10E1',
  'U+10E2',
  'U+10E3',
  'U+10E4',
  'U+10E5',
  'U+10E6',
  'U+10E7',
  'U+10E8',
  'U+10E9',
  'U+10EA',
  'U+10EB',
  'U+10EC',
  'U+10ED',
  'U+10EE',
  'U+10EF',
  'U+10F0',
  'U+10F1',
  'U+10F2',
  'U+10F3',
  'U+10F4',
  'U+10F5',
  'U+10F6',
  'U+10F7',
  'U+10F8',
  'U+10F9',
  'U+10FA',
  'U+10FB',
  'U+10FC',
  'U+10FD',
  'U+10FE',
  'U+10FF',
])

const E68R19_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R19Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R19In (list, v) {
  for (const x of list) { if (E68R19Lower(x) === v) return true }
  return false
}

function E68R19Classify (tok) {
  const v = E68R19Lower(String(tok == null ? '' : tok).trim())
  if (E68R19In(E68R19_BLOCK, v)) return E68R19_CLASS.BLOCK
  if (E68R19In(E68R19_WARN, v)) return E68R19_CLASS.WARN
  if (E68R19In(E68R19_ALLOW, v)) return E68R19_CLASS.ALLOW
  return E68R19_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R19_CLASS: E68R19_CLASS,
  E68R19_BLOCK: E68R19_BLOCK,
  E68R19_WARN: E68R19_WARN,
  E68R19_ALLOW: E68R19_ALLOW,
  E68R19Classify: E68R19Classify
})
