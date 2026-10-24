'use strict'

// e70georgiancatalogguard.js —— 格鲁吉亚文字码位目录。
//
// 威胁模型：
//   格鲁吉亚字母含与拉丁大写近似的字形，混排可做视觉仿冒，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E70T23_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T23_BLOCK = Object.freeze([
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

const E70T23_WARN = Object.freeze([
])

const E70T23_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T23Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T23In (list, v) {
  for (const x of list) { if (E70T23Lower(x) === v) return true }
  return false
}

function E70T23Classify (tok) {
  const v = E70T23Lower(String(tok == null ? '' : tok))
  if (E70T23In(E70T23_BLOCK, v)) return E70T23_CLASS.BLOCK
  if (E70T23In(E70T23_WARN, v)) return E70T23_CLASS.WARN
  if (E70T23In(E70T23_ALLOW, v)) return E70T23_CLASS.ALLOW
  return E70T23_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T23_CLASS: E70T23_CLASS,
  E70T23_BLOCK: E70T23_BLOCK,
  E70T23_WARN: E70T23_WARN,
  E70T23_ALLOW: E70T23_ALLOW,
  E70T23Classify: E70T23Classify
})
