'use strict'

// e68currencycatalogguard.js —— 货币符号码位目录。
//
// 威胁模型：
//   非标准货币符号常被用于钓鱼界面与财务文本伪造，
//   展示与解析应按码点而非字形。纯字符查表，不用正则。

const E68R23_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R23_BLOCK = Object.freeze([
])

const E68R23_WARN = Object.freeze([
  'U+20A0',
  'U+20A1',
  'U+20A2',
  'U+20A3',
  'U+20A4',
  'U+20A5',
  'U+20A6',
  'U+20A7',
  'U+20A8',
  'U+20A9',
  'U+20AA',
  'U+20AB',
  'U+20AC',
  'U+20AD',
  'U+20AE',
  'U+20AF',
  'U+20B0',
  'U+20B1',
  'U+20B2',
  'U+20B3',
  'U+20B4',
  'U+20B5',
  'U+20B6',
  'U+20B7',
  'U+20B8',
  'U+20B9',
  'U+20BA',
  'U+20BB',
  'U+20BC',
  'U+20BD',
  'U+20BE',
  'U+20BF',
  'U+20C0',
  'U+20C1',
  'U+20C2',
  'U+20C3',
  'U+20C4',
  'U+20C5',
  'U+20C6',
  'U+20C7',
  'U+20C8',
  'U+20C9',
  'U+20CA',
  'U+20CB',
  'U+20CC',
  'U+20CD',
  'U+20CE',
  'U+20CF',
])

const E68R23_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R23Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R23In (list, v) {
  for (const x of list) { if (E68R23Lower(x) === v) return true }
  return false
}

function E68R23Classify (tok) {
  const v = E68R23Lower(String(tok == null ? '' : tok).trim())
  if (E68R23In(E68R23_BLOCK, v)) return E68R23_CLASS.BLOCK
  if (E68R23In(E68R23_WARN, v)) return E68R23_CLASS.WARN
  if (E68R23In(E68R23_ALLOW, v)) return E68R23_CLASS.ALLOW
  return E68R23_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R23_CLASS: E68R23_CLASS,
  E68R23_BLOCK: E68R23_BLOCK,
  E68R23_WARN: E68R23_WARN,
  E68R23_ALLOW: E68R23_ALLOW,
  E68R23Classify: E68R23Classify
})
