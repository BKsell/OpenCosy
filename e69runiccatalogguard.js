'use strict'

// e69runiccatalogguard.js —— 如尼文字码位目录。
//
// 威胁模型：
//   如尼字母与部分拉丁大写近似且在常规字段无正当用途，可做视觉仿冒，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E69T12_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T12_BLOCK = Object.freeze([
  'U+16A0',
  'U+16A1',
  'U+16A2',
  'U+16A3',
  'U+16A4',
  'U+16A5',
  'U+16A6',
  'U+16A7',
  'U+16A8',
  'U+16A9',
  'U+16AA',
  'U+16AB',
  'U+16AC',
  'U+16AD',
  'U+16AE',
  'U+16AF',
  'U+16B0',
  'U+16B1',
  'U+16B2',
  'U+16B3',
  'U+16B4',
  'U+16B5',
  'U+16B6',
  'U+16B7',
  'U+16B8',
  'U+16B9',
  'U+16BA',
  'U+16BB',
  'U+16BC',
  'U+16BD',
  'U+16BE',
  'U+16BF',
  'U+16C0',
  'U+16C1',
  'U+16C2',
  'U+16C3',
  'U+16C4',
  'U+16C5',
  'U+16C6',
  'U+16C7',
  'U+16C8',
  'U+16C9',
  'U+16CA',
  'U+16CB',
  'U+16CC',
  'U+16CD',
  'U+16CE',
  'U+16CF',
  'U+16D0',
  'U+16D1',
  'U+16D2',
  'U+16D3',
  'U+16D4',
  'U+16D5',
  'U+16D6',
  'U+16D7',
  'U+16D8',
  'U+16D9',
  'U+16DA',
  'U+16DB',
  'U+16DC',
  'U+16DD',
  'U+16DE',
  'U+16DF',
  'U+16E0',
  'U+16E1',
  'U+16E2',
  'U+16E3',
  'U+16E4',
  'U+16E5',
  'U+16E6',
  'U+16E7',
  'U+16E8',
  'U+16E9',
  'U+16EA',
  'U+16EB',
  'U+16EC',
  'U+16ED',
  'U+16EE',
  'U+16EF',
  'U+16F0',
  'U+16F1',
  'U+16F2',
  'U+16F3',
  'U+16F4',
  'U+16F5',
  'U+16F6',
  'U+16F7',
  'U+16F8',
  'U+16F9',
  'U+16FA',
  'U+16FB',
  'U+16FC',
  'U+16FD',
  'U+16FE',
  'U+16FF',
])

const E69T12_WARN = Object.freeze([
])

const E69T12_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T12Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T12In (list, v) {
  for (const x of list) { if (E69T12Lower(x) === v) return true }
  return false
}

function E69T12Classify (tok) {
  const v = E69T12Lower(String(tok == null ? '' : tok))
  if (E69T12In(E69T12_BLOCK, v)) return E69T12_CLASS.BLOCK
  if (E69T12In(E69T12_WARN, v)) return E69T12_CLASS.WARN
  if (E69T12In(E69T12_ALLOW, v)) return E69T12_CLASS.ALLOW
  return E69T12_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T12_CLASS: E69T12_CLASS,
  E69T12_BLOCK: E69T12_BLOCK,
  E69T12_WARN: E69T12_WARN,
  E69T12_ALLOW: E69T12_ALLOW,
  E69T12Classify: E69T12Classify
})
