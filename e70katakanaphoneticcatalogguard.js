'use strict'

// e70katakanaphoneticcatalogguard.js —— 片假名语音扩展码位目录。
//
// 威胁模型：
//   小字片假名扩展在标识符中无正当用途，可隐藏非 ASCII 数据，
//   应直接拒绝。纯字符查表，不用正则。

const E70T57_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E70T57_BLOCK = Object.freeze([
  'U+31F0',
  'U+31F1',
  'U+31F2',
  'U+31F3',
  'U+31F4',
  'U+31F5',
  'U+31F6',
  'U+31F7',
  'U+31F8',
  'U+31F9',
  'U+31FA',
  'U+31FB',
  'U+31FC',
  'U+31FD',
  'U+31FE',
  'U+31FF',
])

const E70T57_WARN = Object.freeze([
])

const E70T57_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E70T57Lower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E70T57In (list, v) {
  for (const x of list) { if (E70T57Lower(x) === v) return true }
  return false
}

function E70T57Classify (tok) {
  const v = E70T57Lower(String(tok == null ? '' : tok))
  if (E70T57In(E70T57_BLOCK, v)) return E70T57_CLASS.BLOCK
  if (E70T57In(E70T57_WARN, v)) return E70T57_CLASS.WARN
  if (E70T57In(E70T57_ALLOW, v)) return E70T57_CLASS.ALLOW
  return E70T57_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E70T57_CLASS: E70T57_CLASS,
  E70T57_BLOCK: E70T57_BLOCK,
  E70T57_WARN: E70T57_WARN,
  E70T57_ALLOW: E70T57_ALLOW,
  E70T57Classify: E70T57Classify
})
