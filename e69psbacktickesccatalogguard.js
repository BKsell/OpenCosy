'use strict'

// e69psbacktickesccatalogguard.js —— PowerShell 反引号转义字节目录。
//
// 威胁模型：
//   PowerShell 用反引号转义 引号/$/换行等特殊字符，剥离后还原危险字符，可混淆命令注入载荷，
//   危险字符转义应阻断。纯字符查表，不用正则。

const E69PBT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69PBT_BLOCK = Object.freeze([
  '`0',
  '`a',
  '`b',
  '`n',
  '`r',
  '`"',
  '`\'',
  '``',
])

const E69PBT_WARN = Object.freeze([
  '`t',
  '`$',
])

const E69PBT_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69PBTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69PBTIn (list, v) {
  for (const x of list) { if (E69PBTLower(x) === v) return true }
  return false
}

function E69PBTClassify (tok) {
  const v = E69PBTLower(String(tok == null ? '' : tok))
  if (E69PBTIn(E69PBT_BLOCK, v)) return E69PBT_CLASS.BLOCK
  if (E69PBTIn(E69PBT_WARN, v)) return E69PBT_CLASS.WARN
  if (E69PBTIn(E69PBT_ALLOW, v)) return E69PBT_CLASS.ALLOW
  return E69PBT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69PBT_CLASS: E69PBT_CLASS,
  E69PBT_BLOCK: E69PBT_BLOCK,
  E69PBT_WARN: E69PBT_WARN,
  E69PBT_ALLOW: E69PBT_ALLOW,
  E69PBTClassify: E69PBTClassify
})
