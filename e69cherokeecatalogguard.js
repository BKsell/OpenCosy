'use strict'

// e69cherokeecatalogguard.js —— 切罗基文字码位目录。
//
// 威胁模型：
//   切罗基字母含与拉丁大写近似的字形，且在常规字段中无正当用途，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E69T10_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T10_BLOCK = Object.freeze([
  'U+13A0',
  'U+13A1',
  'U+13A2',
  'U+13A3',
  'U+13A4',
  'U+13A5',
  'U+13A6',
  'U+13A7',
  'U+13A8',
  'U+13A9',
  'U+13AA',
  'U+13AB',
  'U+13AC',
  'U+13AD',
  'U+13AE',
  'U+13AF',
  'U+13B0',
  'U+13B1',
  'U+13B2',
  'U+13B3',
  'U+13B4',
  'U+13B5',
  'U+13B6',
  'U+13B7',
  'U+13B8',
  'U+13B9',
  'U+13BA',
  'U+13BB',
  'U+13BC',
  'U+13BD',
  'U+13BE',
  'U+13BF',
  'U+13C0',
  'U+13C1',
  'U+13C2',
  'U+13C3',
  'U+13C4',
  'U+13C5',
  'U+13C6',
  'U+13C7',
  'U+13C8',
  'U+13C9',
  'U+13CA',
  'U+13CB',
  'U+13CC',
  'U+13CD',
  'U+13CE',
  'U+13CF',
  'U+13D0',
  'U+13D1',
  'U+13D2',
  'U+13D3',
  'U+13D4',
  'U+13D5',
  'U+13D6',
  'U+13D7',
  'U+13D8',
  'U+13D9',
  'U+13DA',
  'U+13DB',
  'U+13DC',
  'U+13DD',
  'U+13DE',
  'U+13DF',
  'U+13E0',
  'U+13E1',
  'U+13E2',
  'U+13E3',
  'U+13E4',
  'U+13E5',
  'U+13E6',
  'U+13E7',
  'U+13E8',
  'U+13E9',
  'U+13EA',
  'U+13EB',
  'U+13EC',
  'U+13ED',
  'U+13EE',
  'U+13EF',
  'U+13F0',
  'U+13F1',
  'U+13F2',
  'U+13F3',
  'U+13F4',
  'U+13F5',
  'U+13F6',
  'U+13F7',
  'U+13F8',
  'U+13F9',
  'U+13FA',
  'U+13FB',
  'U+13FC',
  'U+13FD',
  'U+13FE',
  'U+13FF',
])

const E69T10_WARN = Object.freeze([
])

const E69T10_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T10Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T10In (list, v) {
  for (const x of list) { if (E69T10Lower(x) === v) return true }
  return false
}

function E69T10Classify (tok) {
  const v = E69T10Lower(String(tok == null ? '' : tok))
  if (E69T10In(E69T10_BLOCK, v)) return E69T10_CLASS.BLOCK
  if (E69T10In(E69T10_WARN, v)) return E69T10_CLASS.WARN
  if (E69T10In(E69T10_ALLOW, v)) return E69T10_CLASS.ALLOW
  return E69T10_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T10_CLASS: E69T10_CLASS,
  E69T10_BLOCK: E69T10_BLOCK,
  E69T10_WARN: E69T10_WARN,
  E69T10_ALLOW: E69T10_ALLOW,
  E69T10Classify: E69T10Classify
})
