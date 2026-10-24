'use strict'

// e69copticcatalogguard.js —— 科普特文字码位目录。
//
// 威胁模型：
//   科普特字母与部分希腊大写字形近似，混排可绕过同形检测，
//   标识符使用应拒绝。纯字符查表，不用正则。

const E69T16_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T16_BLOCK = Object.freeze([
  'U+2C80',
  'U+2C81',
  'U+2C82',
  'U+2C83',
  'U+2C84',
  'U+2C85',
  'U+2C86',
  'U+2C87',
  'U+2C88',
  'U+2C89',
  'U+2C8A',
  'U+2C8B',
  'U+2C8C',
  'U+2C8D',
  'U+2C8E',
  'U+2C8F',
  'U+2C90',
  'U+2C91',
  'U+2C92',
  'U+2C93',
  'U+2C94',
  'U+2C95',
  'U+2C96',
  'U+2C97',
  'U+2C98',
  'U+2C99',
  'U+2C9A',
  'U+2C9B',
  'U+2C9C',
  'U+2C9D',
  'U+2C9E',
  'U+2C9F',
  'U+2CA0',
  'U+2CA1',
  'U+2CA2',
  'U+2CA3',
  'U+2CA4',
  'U+2CA5',
  'U+2CA6',
  'U+2CA7',
  'U+2CA8',
  'U+2CA9',
  'U+2CAA',
  'U+2CAB',
  'U+2CAC',
  'U+2CAD',
  'U+2CAE',
  'U+2CAF',
  'U+2CB0',
  'U+2CB1',
  'U+2CB2',
  'U+2CB3',
  'U+2CB4',
  'U+2CB5',
  'U+2CB6',
  'U+2CB7',
  'U+2CB8',
  'U+2CB9',
  'U+2CBA',
  'U+2CBB',
  'U+2CBC',
  'U+2CBD',
  'U+2CBE',
  'U+2CBF',
  'U+2CC0',
  'U+2CC1',
  'U+2CC2',
  'U+2CC3',
  'U+2CC4',
  'U+2CC5',
  'U+2CC6',
  'U+2CC7',
  'U+2CC8',
  'U+2CC9',
  'U+2CCA',
  'U+2CCB',
  'U+2CCC',
  'U+2CCD',
  'U+2CCE',
  'U+2CCF',
  'U+2CD0',
  'U+2CD1',
  'U+2CD2',
  'U+2CD3',
  'U+2CD4',
  'U+2CD5',
  'U+2CD6',
  'U+2CD7',
  'U+2CD8',
  'U+2CD9',
  'U+2CDA',
  'U+2CDB',
  'U+2CDC',
  'U+2CDD',
  'U+2CDE',
  'U+2CDF',
  'U+2CE0',
  'U+2CE1',
  'U+2CE2',
  'U+2CE3',
  'U+2CE4',
  'U+2CE5',
  'U+2CE6',
  'U+2CE7',
  'U+2CE8',
  'U+2CE9',
  'U+2CEA',
  'U+2CEB',
  'U+2CEC',
  'U+2CED',
  'U+2CEE',
  'U+2CEF',
  'U+2CF0',
  'U+2CF1',
  'U+2CF2',
  'U+2CF3',
  'U+2CF4',
  'U+2CF5',
  'U+2CF6',
  'U+2CF7',
  'U+2CF8',
  'U+2CF9',
  'U+2CFA',
  'U+2CFB',
  'U+2CFC',
  'U+2CFD',
  'U+2CFE',
  'U+2CFF',
])

const E69T16_WARN = Object.freeze([
])

const E69T16_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T16Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T16In (list, v) {
  for (const x of list) { if (E69T16Lower(x) === v) return true }
  return false
}

function E69T16Classify (tok) {
  const v = E69T16Lower(String(tok == null ? '' : tok))
  if (E69T16In(E69T16_BLOCK, v)) return E69T16_CLASS.BLOCK
  if (E69T16In(E69T16_WARN, v)) return E69T16_CLASS.WARN
  if (E69T16In(E69T16_ALLOW, v)) return E69T16_CLASS.ALLOW
  return E69T16_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T16_CLASS: E69T16_CLASS,
  E69T16_BLOCK: E69T16_BLOCK,
  E69T16_WARN: E69T16_WARN,
  E69T16_ALLOW: E69T16_ALLOW,
  E69T16Classify: E69T16Classify
})
