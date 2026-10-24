'use strict'

// e70phoneticextcatalogguard.js —— 音标扩展码位目录。
//
// 威胁模型：
//   音标扩展含大量与拉丁字母近似的小字与组合字形，可绕过字形匹配，
//   标识符使用需 NFKC 归一化复核。纯字符查表，不用正则。

const E70T34_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T34_BLOCK = Object.freeze([
])

const E70T34_WARN = Object.freeze([
  'U+1D00',
  'U+1D01',
  'U+1D02',
  'U+1D03',
  'U+1D04',
  'U+1D05',
  'U+1D06',
  'U+1D07',
  'U+1D08',
  'U+1D09',
  'U+1D0A',
  'U+1D0B',
  'U+1D0C',
  'U+1D0D',
  'U+1D0E',
  'U+1D0F',
  'U+1D10',
  'U+1D11',
  'U+1D12',
  'U+1D13',
  'U+1D14',
  'U+1D15',
  'U+1D16',
  'U+1D17',
  'U+1D18',
  'U+1D19',
  'U+1D1A',
  'U+1D1B',
  'U+1D1C',
  'U+1D1D',
  'U+1D1E',
  'U+1D1F',
  'U+1D20',
  'U+1D21',
  'U+1D22',
  'U+1D23',
  'U+1D24',
  'U+1D25',
  'U+1D26',
  'U+1D27',
  'U+1D28',
  'U+1D29',
  'U+1D2A',
  'U+1D2B',
  'U+1D2C',
  'U+1D2D',
  'U+1D2E',
  'U+1D2F',
  'U+1D30',
  'U+1D31',
  'U+1D32',
  'U+1D33',
  'U+1D34',
  'U+1D35',
  'U+1D36',
  'U+1D37',
  'U+1D38',
  'U+1D39',
  'U+1D3A',
  'U+1D3B',
  'U+1D3C',
  'U+1D3D',
  'U+1D3E',
  'U+1D3F',
  'U+1D40',
  'U+1D41',
  'U+1D42',
  'U+1D43',
  'U+1D44',
  'U+1D45',
  'U+1D46',
  'U+1D47',
  'U+1D48',
  'U+1D49',
  'U+1D4A',
  'U+1D4B',
  'U+1D4C',
  'U+1D4D',
  'U+1D4E',
  'U+1D4F',
  'U+1D50',
  'U+1D51',
  'U+1D52',
  'U+1D53',
  'U+1D54',
  'U+1D55',
  'U+1D56',
  'U+1D57',
  'U+1D58',
  'U+1D59',
  'U+1D5A',
  'U+1D5B',
  'U+1D5C',
  'U+1D5D',
  'U+1D5E',
  'U+1D5F',
  'U+1D60',
  'U+1D61',
  'U+1D62',
  'U+1D63',
  'U+1D64',
  'U+1D65',
  'U+1D66',
  'U+1D67',
  'U+1D68',
  'U+1D69',
  'U+1D6A',
  'U+1D6B',
  'U+1D6C',
  'U+1D6D',
  'U+1D6E',
  'U+1D6F',
  'U+1D70',
  'U+1D71',
  'U+1D72',
  'U+1D73',
  'U+1D74',
  'U+1D75',
  'U+1D76',
  'U+1D77',
  'U+1D78',
  'U+1D79',
  'U+1D7A',
  'U+1D7B',
  'U+1D7C',
  'U+1D7D',
  'U+1D7E',
  'U+1D7F',
])

const E70T34_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T34Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T34In (list, v) {
  for (const x of list) { if (E70T34Lower(x) === v) return true }
  return false
}

function E70T34Classify (tok) {
  const v = E70T34Lower(String(tok == null ? '' : tok))
  if (E70T34In(E70T34_BLOCK, v)) return E70T34_CLASS.BLOCK
  if (E70T34In(E70T34_WARN, v)) return E70T34_CLASS.WARN
  if (E70T34In(E70T34_ALLOW, v)) return E70T34_CLASS.ALLOW
  return E70T34_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T34_CLASS: E70T34_CLASS,
  E70T34_BLOCK: E70T34_BLOCK,
  E70T34_WARN: E70T34_WARN,
  E70T34_ALLOW: E70T34_ALLOW,
  E70T34Classify: E70T34Classify
})
