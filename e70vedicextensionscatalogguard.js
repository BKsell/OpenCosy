'use strict'

// e70vedicextensionscatalogguard.js —— 吠陀扩展组合记号目录。
//
// 威胁模型：
//   吠陀扩展记号叠加在基字符上不占独立视觉位，可隐藏码点，
//   应直接拒绝。纯字符查表，不用正则。

const E70T33_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T33_BLOCK = Object.freeze([
  'U+1CD0',
  'U+1CD1',
  'U+1CD2',
  'U+1CD3',
  'U+1CD4',
  'U+1CD5',
  'U+1CD6',
  'U+1CD7',
  'U+1CD8',
  'U+1CD9',
  'U+1CDA',
  'U+1CDB',
  'U+1CDC',
  'U+1CDD',
  'U+1CDE',
  'U+1CDF',
  'U+1CE0',
  'U+1CE1',
  'U+1CE2',
  'U+1CE3',
  'U+1CE4',
  'U+1CE5',
  'U+1CE6',
  'U+1CE7',
  'U+1CE8',
  'U+1CE9',
  'U+1CEA',
  'U+1CEB',
  'U+1CEC',
  'U+1CED',
  'U+1CEE',
  'U+1CEF',
  'U+1CF0',
  'U+1CF1',
  'U+1CF2',
  'U+1CF3',
  'U+1CF4',
  'U+1CF5',
  'U+1CF6',
  'U+1CF7',
  'U+1CF8',
  'U+1CF9',
  'U+1CFA',
  'U+1CFB',
  'U+1CFC',
  'U+1CFD',
  'U+1CFE',
  'U+1CFF',
])

const E70T33_WARN = Object.freeze([
])

const E70T33_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T33Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T33In (list, v) {
  for (const x of list) { if (E70T33Lower(x) === v) return true }
  return false
}

function E70T33Classify (tok) {
  const v = E70T33Lower(String(tok == null ? '' : tok))
  if (E70T33In(E70T33_BLOCK, v)) return E70T33_CLASS.BLOCK
  if (E70T33In(E70T33_WARN, v)) return E70T33_CLASS.WARN
  if (E70T33In(E70T33_ALLOW, v)) return E70T33_CLASS.ALLOW
  return E70T33_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T33_CLASS: E70T33_CLASS,
  E70T33_BLOCK: E70T33_BLOCK,
  E70T33_WARN: E70T33_WARN,
  E70T33_ALLOW: E70T33_ALLOW,
  E70T33Classify: E70T33Classify
})
