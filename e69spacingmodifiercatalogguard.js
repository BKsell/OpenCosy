'use strict'

// e69spacingmodifiercatalogguard.js —— 占位修饰字母码位目录。
//
// 威胁模型：
//   修饰字母（如上标变体）与普通字母视觉近似且不占组合位，可绕过长度与字形检查，
//   应规范化后比较。纯字符查表，不用正则。

const E69T04_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T04_BLOCK = Object.freeze([
])

const E69T04_WARN = Object.freeze([
  'U+02B0',
  'U+02B1',
  'U+02B2',
  'U+02B3',
  'U+02B4',
  'U+02B5',
  'U+02B6',
  'U+02B7',
  'U+02B8',
  'U+02B9',
  'U+02BA',
  'U+02BB',
  'U+02BC',
  'U+02BD',
  'U+02BE',
  'U+02BF',
  'U+02C0',
  'U+02C1',
  'U+02C2',
  'U+02C3',
  'U+02C4',
  'U+02C5',
  'U+02C6',
  'U+02C7',
  'U+02C8',
  'U+02C9',
  'U+02CA',
  'U+02CB',
  'U+02CC',
  'U+02CD',
  'U+02CE',
  'U+02CF',
  'U+02D0',
  'U+02D1',
  'U+02D2',
  'U+02D3',
  'U+02D4',
  'U+02D5',
  'U+02D6',
  'U+02D7',
  'U+02D8',
  'U+02D9',
  'U+02DA',
  'U+02DB',
  'U+02DC',
  'U+02DD',
  'U+02DE',
  'U+02DF',
  'U+02E0',
  'U+02E1',
  'U+02E2',
  'U+02E3',
  'U+02E4',
  'U+02E5',
  'U+02E6',
  'U+02E7',
  'U+02E8',
  'U+02E9',
  'U+02EA',
  'U+02EB',
  'U+02EC',
  'U+02ED',
  'U+02EE',
  'U+02EF',
  'U+02F0',
  'U+02F1',
  'U+02F2',
  'U+02F3',
  'U+02F4',
  'U+02F5',
  'U+02F6',
  'U+02F7',
  'U+02F8',
  'U+02F9',
  'U+02FA',
  'U+02FB',
  'U+02FC',
  'U+02FD',
  'U+02FE',
  'U+02FF',
])

const E69T04_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T04Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T04In (list, v) {
  for (const x of list) { if (E69T04Lower(x) === v) return true }
  return false
}

function E69T04Classify (tok) {
  const v = E69T04Lower(String(tok == null ? '' : tok))
  if (E69T04In(E69T04_BLOCK, v)) return E69T04_CLASS.BLOCK
  if (E69T04In(E69T04_WARN, v)) return E69T04_CLASS.WARN
  if (E69T04In(E69T04_ALLOW, v)) return E69T04_CLASS.ALLOW
  return E69T04_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T04_CLASS: E69T04_CLASS,
  E69T04_BLOCK: E69T04_BLOCK,
  E69T04_WARN: E69T04_WARN,
  E69T04_ALLOW: E69T04_ALLOW,
  E69T04Classify: E69T04Classify
})
