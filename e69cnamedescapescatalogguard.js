'use strict'

// e69cnamedescapescatalogguard.js —— C 风格命名转义字节目录。
//
// 威胁模型：
//   \0 \n \r \\ \" 等命名转义在源码/配置中还原控制符与引号，可隐藏注入分隔符，
//   危险字节命名转义应阻断。纯字符查表，不用正则。

const E69CNE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69CNE_BLOCK = Object.freeze([
  '\\0',
  '\\a',
  '\\b',
  '\\n',
  '\\v',
  '\\f',
  '\\r',
  '\\"',
  '\\\'',
  '\\\\',
])

const E69CNE_WARN = Object.freeze([
  '\\t',
])

const E69CNE_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69CNELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69CNEIn (list, v) {
  for (const x of list) { if (E69CNELower(x) === v) return true }
  return false
}

function E69CNEClassify (tok) {
  const v = E69CNELower(String(tok == null ? '' : tok))
  if (E69CNEIn(E69CNE_BLOCK, v)) return E69CNE_CLASS.BLOCK
  if (E69CNEIn(E69CNE_WARN, v)) return E69CNE_CLASS.WARN
  if (E69CNEIn(E69CNE_ALLOW, v)) return E69CNE_CLASS.ALLOW
  return E69CNE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69CNE_CLASS: E69CNE_CLASS,
  E69CNE_BLOCK: E69CNE_BLOCK,
  E69CNE_WARN: E69CNE_WARN,
  E69CNE_ALLOW: E69CNE_ALLOW,
  E69CNEClassify: E69CNEClassify
})
