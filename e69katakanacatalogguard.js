'use strict'

// e69katakanacatalogguard.js —— 片假名码位目录。
//
// 威胁模型：
//   片假名在机器标识符中无正当用途，全角片假名还可能与符号混淆，
//   机器字段应拒绝。纯字符查表，不用正则。

const E69T26_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T26_BLOCK = Object.freeze([
  'U+30A0',
  'U+30A1',
  'U+30A2',
  'U+30A3',
  'U+30A4',
  'U+30A5',
  'U+30A6',
  'U+30A7',
  'U+30A8',
  'U+30A9',
  'U+30AA',
  'U+30AB',
  'U+30AC',
  'U+30AD',
  'U+30AE',
  'U+30AF',
  'U+30B0',
  'U+30B1',
  'U+30B2',
  'U+30B3',
  'U+30B4',
  'U+30B5',
  'U+30B6',
  'U+30B7',
  'U+30B8',
  'U+30B9',
  'U+30BA',
  'U+30BB',
  'U+30BC',
  'U+30BD',
  'U+30BE',
  'U+30BF',
  'U+30C0',
  'U+30C1',
  'U+30C2',
  'U+30C3',
  'U+30C4',
  'U+30C5',
  'U+30C6',
  'U+30C7',
  'U+30C8',
  'U+30C9',
  'U+30CA',
  'U+30CB',
  'U+30CC',
  'U+30CD',
  'U+30CE',
  'U+30CF',
  'U+30D0',
  'U+30D1',
  'U+30D2',
  'U+30D3',
  'U+30D4',
  'U+30D5',
  'U+30D6',
  'U+30D7',
  'U+30D8',
  'U+30D9',
  'U+30DA',
  'U+30DB',
  'U+30DC',
  'U+30DD',
  'U+30DE',
  'U+30DF',
  'U+30E0',
  'U+30E1',
  'U+30E2',
  'U+30E3',
  'U+30E4',
  'U+30E5',
  'U+30E6',
  'U+30E7',
  'U+30E8',
  'U+30E9',
  'U+30EA',
  'U+30EB',
  'U+30EC',
  'U+30ED',
  'U+30EE',
  'U+30EF',
  'U+30F0',
  'U+30F1',
  'U+30F2',
  'U+30F3',
  'U+30F4',
  'U+30F5',
  'U+30F6',
  'U+30F7',
  'U+30F8',
  'U+30F9',
  'U+30FA',
  'U+30FB',
  'U+30FC',
  'U+30FD',
  'U+30FE',
  'U+30FF',
])

const E69T26_WARN = Object.freeze([
])

const E69T26_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T26Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T26In (list, v) {
  for (const x of list) { if (E69T26Lower(x) === v) return true }
  return false
}

function E69T26Classify (tok) {
  const v = E69T26Lower(String(tok == null ? '' : tok))
  if (E69T26In(E69T26_BLOCK, v)) return E69T26_CLASS.BLOCK
  if (E69T26In(E69T26_WARN, v)) return E69T26_CLASS.WARN
  if (E69T26In(E69T26_ALLOW, v)) return E69T26_CLASS.ALLOW
  return E69T26_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T26_CLASS: E69T26_CLASS,
  E69T26_BLOCK: E69T26_BLOCK,
  E69T26_WARN: E69T26_WARN,
  E69T26_ALLOW: E69T26_ALLOW,
  E69T26Classify: E69T26Classify
})
