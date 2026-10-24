'use strict'

// e70sundanesecatalogguard.js —— 巽他文字码位目录。
//
// 威胁模型：
//   巽他文在常规机器字段无正当用途，
//   应直接拒绝。纯字符查表，不用正则。

const E70T30_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T30_BLOCK = Object.freeze([
  'U+1B80',
  'U+1B81',
  'U+1B82',
  'U+1B83',
  'U+1B84',
  'U+1B85',
  'U+1B86',
  'U+1B87',
  'U+1B88',
  'U+1B89',
  'U+1B8A',
  'U+1B8B',
  'U+1B8C',
  'U+1B8D',
  'U+1B8E',
  'U+1B8F',
  'U+1B90',
  'U+1B91',
  'U+1B92',
  'U+1B93',
  'U+1B94',
  'U+1B95',
  'U+1B96',
  'U+1B97',
  'U+1B98',
  'U+1B99',
  'U+1B9A',
  'U+1B9B',
  'U+1B9C',
  'U+1B9D',
  'U+1B9E',
  'U+1B9F',
  'U+1BA0',
  'U+1BA1',
  'U+1BA2',
  'U+1BA3',
  'U+1BA4',
  'U+1BA5',
  'U+1BA6',
  'U+1BA7',
  'U+1BA8',
  'U+1BA9',
  'U+1BAA',
  'U+1BAB',
  'U+1BAC',
  'U+1BAD',
  'U+1BAE',
  'U+1BAF',
  'U+1BB0',
  'U+1BB1',
  'U+1BB2',
  'U+1BB3',
  'U+1BB4',
  'U+1BB5',
  'U+1BB6',
  'U+1BB7',
  'U+1BB8',
  'U+1BB9',
  'U+1BBA',
  'U+1BBB',
  'U+1BBC',
  'U+1BBD',
  'U+1BBE',
  'U+1BBF',
])

const E70T30_WARN = Object.freeze([
])

const E70T30_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T30Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T30In (list, v) {
  for (const x of list) { if (E70T30Lower(x) === v) return true }
  return false
}

function E70T30Classify (tok) {
  const v = E70T30Lower(String(tok == null ? '' : tok))
  if (E70T30In(E70T30_BLOCK, v)) return E70T30_CLASS.BLOCK
  if (E70T30In(E70T30_WARN, v)) return E70T30_CLASS.WARN
  if (E70T30In(E70T30_ALLOW, v)) return E70T30_CLASS.ALLOW
  return E70T30_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T30_CLASS: E70T30_CLASS,
  E70T30_BLOCK: E70T30_BLOCK,
  E70T30_WARN: E70T30_WARN,
  E70T30_ALLOW: E70T30_ALLOW,
  E70T30Classify: E70T30Classify
})
