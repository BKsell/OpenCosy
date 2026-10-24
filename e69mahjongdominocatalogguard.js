'use strict'

// e69mahjongdominocatalogguard.js —— 麻将与多米诺骨牌目录。
//
// 威胁模型：
//   麻将/多米诺符号在机器字段无正当用途，可用于界面符号仿冒，
//   结构化字段应拒绝。纯字符查表，不用正则。

const E69U11_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69U11_BLOCK = Object.freeze([
  'U+1F000',
  'U+1F001',
  'U+1F002',
  'U+1F003',
  'U+1F004',
  'U+1F005',
  'U+1F006',
  'U+1F007',
  'U+1F008',
  'U+1F009',
  'U+1F00A',
  'U+1F00B',
  'U+1F00C',
  'U+1F00D',
  'U+1F00E',
  'U+1F00F',
  'U+1F010',
  'U+1F011',
  'U+1F012',
  'U+1F013',
  'U+1F014',
  'U+1F015',
  'U+1F016',
  'U+1F017',
  'U+1F018',
  'U+1F019',
  'U+1F01A',
  'U+1F01B',
  'U+1F01C',
  'U+1F01D',
  'U+1F01E',
  'U+1F01F',
  'U+1F020',
  'U+1F021',
  'U+1F022',
  'U+1F023',
  'U+1F024',
  'U+1F025',
  'U+1F026',
  'U+1F027',
  'U+1F028',
  'U+1F029',
  'U+1F02A',
  'U+1F02B',
  'U+1F02C',
  'U+1F02D',
  'U+1F02E',
  'U+1F02F',
])

const E69U11_WARN = Object.freeze([
])

const E69U11_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69U11Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69U11In (list, v) {
  for (const x of list) { if (E69U11Lower(x) === v) return true }
  return false
}

function E69U11Classify (tok) {
  const v = E69U11Lower(String(tok == null ? '' : tok))
  if (E69U11In(E69U11_BLOCK, v)) return E69U11_CLASS.BLOCK
  if (E69U11In(E69U11_WARN, v)) return E69U11_CLASS.WARN
  if (E69U11In(E69U11_ALLOW, v)) return E69U11_CLASS.ALLOW
  return E69U11_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69U11_CLASS: E69U11_CLASS,
  E69U11_BLOCK: E69U11_BLOCK,
  E69U11_WARN: E69U11_WARN,
  E69U11_ALLOW: E69U11_ALLOW,
  E69U11Classify: E69U11Classify
})
