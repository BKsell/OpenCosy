'use strict'

// e69cyrillicextdcatalogguard.js —— 西里尔扩展 D 码位目录。
//
// 威胁模型：
//   扩展 D 西里尔字符含与拉丁近似的历史字形，常规字段无正当用途，
//   机器字段应拒绝。纯字符查表，不用正则。

const E69T43_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69T43_BLOCK = Object.freeze([
  'U+1E000',
  'U+1E001',
  'U+1E002',
  'U+1E003',
  'U+1E004',
  'U+1E005',
  'U+1E006',
  'U+1E007',
  'U+1E008',
  'U+1E009',
  'U+1E00A',
  'U+1E00B',
  'U+1E00C',
  'U+1E00D',
  'U+1E00E',
  'U+1E00F',
  'U+1E010',
  'U+1E011',
  'U+1E012',
  'U+1E013',
  'U+1E014',
  'U+1E015',
  'U+1E016',
  'U+1E017',
  'U+1E018',
  'U+1E019',
  'U+1E01A',
  'U+1E01B',
  'U+1E01C',
  'U+1E01D',
  'U+1E01E',
  'U+1E01F',
  'U+1E020',
  'U+1E021',
  'U+1E022',
  'U+1E023',
  'U+1E024',
  'U+1E025',
  'U+1E026',
  'U+1E027',
  'U+1E028',
  'U+1E029',
  'U+1E02A',
  'U+1E02B',
  'U+1E02C',
  'U+1E02D',
  'U+1E02E',
  'U+1E02F',
])

const E69T43_WARN = Object.freeze([
])

const E69T43_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69T43Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69T43In (list, v) {
  for (const x of list) { if (E69T43Lower(x) === v) return true }
  return false
}

function E69T43Classify (tok) {
  const v = E69T43Lower(String(tok == null ? '' : tok))
  if (E69T43In(E69T43_BLOCK, v)) return E69T43_CLASS.BLOCK
  if (E69T43In(E69T43_WARN, v)) return E69T43_CLASS.WARN
  if (E69T43In(E69T43_ALLOW, v)) return E69T43_CLASS.ALLOW
  return E69T43_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69T43_CLASS: E69T43_CLASS,
  E69T43_BLOCK: E69T43_BLOCK,
  E69T43_WARN: E69T43_WARN,
  E69T43_ALLOW: E69T43_ALLOW,
  E69T43Classify: E69T43Classify
})
