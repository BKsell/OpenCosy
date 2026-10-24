'use strict'

// e69playingcardscatalogguard.js —— 扑克牌符号码位目录。
//
// 威胁模型：
//   扑克牌符号在机器字段无正当用途，部分与普通字母数字近似，
//   结构化字段应拒绝。纯字符查表，不用正则。

const E69U12_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69U12_BLOCK = Object.freeze([
  'U+1F0A0',
  'U+1F0A1',
  'U+1F0A2',
  'U+1F0A3',
  'U+1F0A4',
  'U+1F0A5',
  'U+1F0A6',
  'U+1F0A7',
  'U+1F0A8',
  'U+1F0A9',
  'U+1F0AA',
  'U+1F0AB',
  'U+1F0AC',
  'U+1F0AD',
  'U+1F0AE',
  'U+1F0AF',
  'U+1F0B0',
  'U+1F0B1',
  'U+1F0B2',
  'U+1F0B3',
  'U+1F0B4',
  'U+1F0B5',
  'U+1F0B6',
  'U+1F0B7',
  'U+1F0B8',
  'U+1F0B9',
  'U+1F0BA',
  'U+1F0BB',
  'U+1F0BC',
  'U+1F0BD',
  'U+1F0BE',
  'U+1F0BF',
  'U+1F0C0',
  'U+1F0C1',
  'U+1F0C2',
  'U+1F0C3',
  'U+1F0C4',
  'U+1F0C5',
  'U+1F0C6',
  'U+1F0C7',
  'U+1F0C8',
  'U+1F0C9',
  'U+1F0CA',
  'U+1F0CB',
  'U+1F0CC',
  'U+1F0CD',
  'U+1F0CE',
  'U+1F0CF',
  'U+1F0D0',
  'U+1F0D1',
  'U+1F0D2',
  'U+1F0D3',
  'U+1F0D4',
  'U+1F0D5',
  'U+1F0D6',
  'U+1F0D7',
  'U+1F0D8',
  'U+1F0D9',
  'U+1F0DA',
  'U+1F0DB',
  'U+1F0DC',
  'U+1F0DD',
  'U+1F0DE',
  'U+1F0DF',
  'U+1F0E0',
  'U+1F0E1',
  'U+1F0E2',
  'U+1F0E3',
  'U+1F0E4',
  'U+1F0E5',
  'U+1F0E6',
  'U+1F0E7',
  'U+1F0E8',
  'U+1F0E9',
  'U+1F0EA',
  'U+1F0EB',
  'U+1F0EC',
  'U+1F0ED',
  'U+1F0EE',
  'U+1F0EF',
  'U+1F0F0',
  'U+1F0F1',
  'U+1F0F2',
  'U+1F0F3',
  'U+1F0F4',
  'U+1F0F5',
  'U+1F0F6',
  'U+1F0F7',
  'U+1F0F8',
  'U+1F0F9',
  'U+1F0FA',
  'U+1F0FB',
  'U+1F0FC',
  'U+1F0FD',
  'U+1F0FE',
  'U+1F0FF',
])

const E69U12_WARN = Object.freeze([
])

const E69U12_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69U12Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69U12In (list, v) {
  for (const x of list) { if (E69U12Lower(x) === v) return true }
  return false
}

function E69U12Classify (tok) {
  const v = E69U12Lower(String(tok == null ? '' : tok))
  if (E69U12In(E69U12_BLOCK, v)) return E69U12_CLASS.BLOCK
  if (E69U12In(E69U12_WARN, v)) return E69U12_CLASS.WARN
  if (E69U12In(E69U12_ALLOW, v)) return E69U12_CLASS.ALLOW
  return E69U12_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69U12_CLASS: E69U12_CLASS,
  E69U12_BLOCK: E69U12_BLOCK,
  E69U12_WARN: E69U12_WARN,
  E69U12_ALLOW: E69U12_ALLOW,
  E69U12Classify: E69U12Classify
})
