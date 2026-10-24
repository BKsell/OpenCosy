'use strict'

// e70buginesecatalogguard.js —— 布吉文字码位目录。
//
// 威胁模型：
//   布吉文在机器字段无正当用途，渲染依赖专用字体，
//   应直接拒绝。纯字符查表，不用正则。

const E70T28_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T28_BLOCK = Object.freeze([
  'U+1A00',
  'U+1A01',
  'U+1A02',
  'U+1A03',
  'U+1A04',
  'U+1A05',
  'U+1A06',
  'U+1A07',
  'U+1A08',
  'U+1A09',
  'U+1A0A',
  'U+1A0B',
  'U+1A0C',
  'U+1A0D',
  'U+1A0E',
  'U+1A0F',
  'U+1A10',
  'U+1A11',
  'U+1A12',
  'U+1A13',
  'U+1A14',
  'U+1A15',
  'U+1A16',
  'U+1A17',
  'U+1A18',
  'U+1A19',
  'U+1A1A',
  'U+1A1B',
  'U+1A1C',
  'U+1A1D',
  'U+1A1E',
  'U+1A1F',
])

const E70T28_WARN = Object.freeze([
])

const E70T28_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T28Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T28In (list, v) {
  for (const x of list) { if (E70T28Lower(x) === v) return true }
  return false
}

function E70T28Classify (tok) {
  const v = E70T28Lower(String(tok == null ? '' : tok))
  if (E70T28In(E70T28_BLOCK, v)) return E70T28_CLASS.BLOCK
  if (E70T28In(E70T28_WARN, v)) return E70T28_CLASS.WARN
  if (E70T28In(E70T28_ALLOW, v)) return E70T28_CLASS.ALLOW
  return E70T28_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T28_CLASS: E70T28_CLASS,
  E70T28_BLOCK: E70T28_BLOCK,
  E70T28_WARN: E70T28_WARN,
  E70T28_ALLOW: E70T28_ALLOW,
  E70T28Classify: E70T28Classify
})
