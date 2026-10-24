'use strict'

// e68kannadacatalogguard.js —— 卡纳达文字码位目录。
//
// 威胁模型：
//   卡纳达文组合序列可绕过精确匹配，
//   应先规范化。纯字符查表，不用正则。

const E68R12_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E68R12_BLOCK = Object.freeze([
])

const E68R12_WARN = Object.freeze([
  'U+0C80',
  'U+0C81',
  'U+0C82',
  'U+0C83',
  'U+0C84',
  'U+0C85',
  'U+0C86',
  'U+0C87',
  'U+0C88',
  'U+0C89',
  'U+0C8A',
  'U+0C8B',
  'U+0C8C',
  'U+0C8D',
  'U+0C8E',
  'U+0C8F',
  'U+0C90',
  'U+0C91',
  'U+0C92',
  'U+0C93',
  'U+0C94',
  'U+0C95',
  'U+0C96',
  'U+0C97',
  'U+0C98',
  'U+0C99',
  'U+0C9A',
  'U+0C9B',
  'U+0C9C',
  'U+0C9D',
  'U+0C9E',
  'U+0C9F',
  'U+0CA0',
  'U+0CA1',
  'U+0CA2',
  'U+0CA3',
  'U+0CA4',
  'U+0CA5',
  'U+0CA6',
  'U+0CA7',
  'U+0CA8',
  'U+0CA9',
  'U+0CAA',
  'U+0CAB',
  'U+0CAC',
  'U+0CAD',
  'U+0CAE',
  'U+0CAF',
  'U+0CB0',
  'U+0CB1',
  'U+0CB2',
  'U+0CB3',
  'U+0CB4',
  'U+0CB5',
  'U+0CB6',
  'U+0CB7',
  'U+0CB8',
  'U+0CB9',
  'U+0CBA',
  'U+0CBB',
  'U+0CBC',
  'U+0CBD',
  'U+0CBE',
  'U+0CBF',
  'U+0CC0',
  'U+0CC1',
  'U+0CC2',
  'U+0CC3',
  'U+0CC4',
  'U+0CC5',
  'U+0CC6',
  'U+0CC7',
  'U+0CC8',
  'U+0CC9',
  'U+0CCA',
  'U+0CCB',
  'U+0CCC',
  'U+0CCD',
  'U+0CCE',
  'U+0CCF',
  'U+0CD0',
  'U+0CD1',
  'U+0CD2',
  'U+0CD3',
  'U+0CD4',
  'U+0CD5',
  'U+0CD6',
  'U+0CD7',
  'U+0CD8',
  'U+0CD9',
  'U+0CDA',
  'U+0CDB',
  'U+0CDC',
  'U+0CDD',
  'U+0CDE',
  'U+0CDF',
  'U+0CE0',
  'U+0CE1',
  'U+0CE2',
  'U+0CE3',
  'U+0CE4',
  'U+0CE5',
  'U+0CE6',
  'U+0CE7',
  'U+0CE8',
  'U+0CE9',
  'U+0CEA',
  'U+0CEB',
  'U+0CEC',
  'U+0CED',
  'U+0CEE',
  'U+0CEF',
  'U+0CF0',
  'U+0CF1',
  'U+0CF2',
  'U+0CF3',
  'U+0CF4',
  'U+0CF5',
  'U+0CF6',
  'U+0CF7',
  'U+0CF8',
  'U+0CF9',
  'U+0CFA',
  'U+0CFB',
  'U+0CFC',
  'U+0CFD',
  'U+0CFE',
  'U+0CFF',
])

const E68R12_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E68R12Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E68R12In (list, v) {
  for (const x of list) { if (E68R12Lower(x) === v) return true }
  return false
}

function E68R12Classify (tok) {
  const v = E68R12Lower(String(tok == null ? '' : tok).trim())
  if (E68R12In(E68R12_BLOCK, v)) return E68R12_CLASS.BLOCK
  if (E68R12In(E68R12_WARN, v)) return E68R12_CLASS.WARN
  if (E68R12In(E68R12_ALLOW, v)) return E68R12_CLASS.ALLOW
  return E68R12_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E68R12_CLASS: E68R12_CLASS,
  E68R12_BLOCK: E68R12_BLOCK,
  E68R12_WARN: E68R12_WARN,
  E68R12_ALLOW: E68R12_ALLOW,
  E68R12Classify: E68R12Classify
})
