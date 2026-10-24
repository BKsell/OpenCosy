'use strict'

// e70georgiansuppcatalogguard.js —— 格鲁吉亚补充码位目录。
//
// 威胁模型：
//   格鲁吉亚补充字符在机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T53_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T53_BLOCK = Object.freeze([
  'U+2D00',
  'U+2D01',
  'U+2D02',
  'U+2D03',
  'U+2D04',
  'U+2D05',
  'U+2D06',
  'U+2D07',
  'U+2D08',
  'U+2D09',
  'U+2D0A',
  'U+2D0B',
  'U+2D0C',
  'U+2D0D',
  'U+2D0E',
  'U+2D0F',
  'U+2D10',
  'U+2D11',
  'U+2D12',
  'U+2D13',
  'U+2D14',
  'U+2D15',
  'U+2D16',
  'U+2D17',
  'U+2D18',
  'U+2D19',
  'U+2D1A',
  'U+2D1B',
  'U+2D1C',
  'U+2D1D',
  'U+2D1E',
  'U+2D1F',
  'U+2D20',
  'U+2D21',
  'U+2D22',
  'U+2D23',
  'U+2D24',
  'U+2D25',
  'U+2D26',
  'U+2D27',
  'U+2D28',
  'U+2D29',
  'U+2D2A',
  'U+2D2B',
  'U+2D2C',
  'U+2D2D',
  'U+2D2E',
  'U+2D2F',
])

const E70T53_WARN = Object.freeze([
])

const E70T53_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T53Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T53In (list, v) {
  for (const x of list) { if (E70T53Lower(x) === v) return true }
  return false
}

function E70T53Classify (tok) {
  const v = E70T53Lower(String(tok == null ? '' : tok))
  if (E70T53In(E70T53_BLOCK, v)) return E70T53_CLASS.BLOCK
  if (E70T53In(E70T53_WARN, v)) return E70T53_CLASS.WARN
  if (E70T53In(E70T53_ALLOW, v)) return E70T53_CLASS.ALLOW
  return E70T53_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T53_CLASS: E70T53_CLASS,
  E70T53_BLOCK: E70T53_BLOCK,
  E70T53_WARN: E70T53_WARN,
  E70T53_ALLOW: E70T53_ALLOW,
  E70T53Classify: E70T53Classify
})
