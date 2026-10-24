'use strict'

// e68gurmukhicatalogguard.js —— 古木基文字码位目录。
//
// 威胁模型：
//   古木基文组合序列可构造同形字符串，
//   标识符使用需复核。纯字符查表，不用正则。

const E68R07_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R07_BLOCK = Object.freeze([
])

const E68R07_WARN = Object.freeze([
  'U+0A00',
  'U+0A01',
  'U+0A02',
  'U+0A03',
  'U+0A04',
  'U+0A05',
  'U+0A06',
  'U+0A07',
  'U+0A08',
  'U+0A09',
  'U+0A0A',
  'U+0A0B',
  'U+0A0C',
  'U+0A0D',
  'U+0A0E',
  'U+0A0F',
  'U+0A10',
  'U+0A11',
  'U+0A12',
  'U+0A13',
  'U+0A14',
  'U+0A15',
  'U+0A16',
  'U+0A17',
  'U+0A18',
  'U+0A19',
  'U+0A1A',
  'U+0A1B',
  'U+0A1C',
  'U+0A1D',
  'U+0A1E',
  'U+0A1F',
  'U+0A20',
  'U+0A21',
  'U+0A22',
  'U+0A23',
  'U+0A24',
  'U+0A25',
  'U+0A26',
  'U+0A27',
  'U+0A28',
  'U+0A29',
  'U+0A2A',
  'U+0A2B',
  'U+0A2C',
  'U+0A2D',
  'U+0A2E',
  'U+0A2F',
  'U+0A30',
  'U+0A31',
  'U+0A32',
  'U+0A33',
  'U+0A34',
  'U+0A35',
  'U+0A36',
  'U+0A37',
  'U+0A38',
  'U+0A39',
  'U+0A3A',
  'U+0A3B',
  'U+0A3C',
  'U+0A3D',
  'U+0A3E',
  'U+0A3F',
  'U+0A40',
  'U+0A41',
  'U+0A42',
  'U+0A43',
  'U+0A44',
  'U+0A45',
  'U+0A46',
  'U+0A47',
  'U+0A48',
  'U+0A49',
  'U+0A4A',
  'U+0A4B',
  'U+0A4C',
  'U+0A4D',
  'U+0A4E',
  'U+0A4F',
  'U+0A50',
  'U+0A51',
  'U+0A52',
  'U+0A53',
  'U+0A54',
  'U+0A55',
  'U+0A56',
  'U+0A57',
  'U+0A58',
  'U+0A59',
  'U+0A5A',
  'U+0A5B',
  'U+0A5C',
  'U+0A5D',
  'U+0A5E',
  'U+0A5F',
  'U+0A60',
  'U+0A61',
  'U+0A62',
  'U+0A63',
  'U+0A64',
  'U+0A65',
  'U+0A66',
  'U+0A67',
  'U+0A68',
  'U+0A69',
  'U+0A6A',
  'U+0A6B',
  'U+0A6C',
  'U+0A6D',
  'U+0A6E',
  'U+0A6F',
  'U+0A70',
  'U+0A71',
  'U+0A72',
  'U+0A73',
  'U+0A74',
  'U+0A75',
  'U+0A76',
  'U+0A77',
  'U+0A78',
  'U+0A79',
  'U+0A7A',
  'U+0A7B',
  'U+0A7C',
  'U+0A7D',
  'U+0A7E',
  'U+0A7F',
])

const E68R07_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R07Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R07In (list, v) {
  for (const x of list) { if (E68R07Lower(x) === v) return true }
  return false
}

function E68R07Classify (tok) {
  const v = E68R07Lower(String(tok == null ? '' : tok).trim())
  if (E68R07In(E68R07_BLOCK, v)) return E68R07_CLASS.BLOCK
  if (E68R07In(E68R07_WARN, v)) return E68R07_CLASS.WARN
  if (E68R07In(E68R07_ALLOW, v)) return E68R07_CLASS.ALLOW
  return E68R07_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R07_CLASS: E68R07_CLASS,
  E68R07_BLOCK: E68R07_BLOCK,
  E68R07_WARN: E68R07_WARN,
  E68R07_ALLOW: E68R07_ALLOW,
  E68R07Classify: E68R07Classify
})
