'use strict'

// e69cmdcaretesccatalogguard.js —— cmd.exe 插入符转义字节目录。
//
// 威胁模型：
//   cmd.exe 用 ^ 转义 & < > | ( ) " 等元字符，插入符在解析阶段被剥离，纯字节黑名单可被 ^< 绕过，
//   危险元字符转义应阻断。纯字符查表，不用正则。

const E69CMC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const E69CMC_BLOCK = Object.freeze([
  '^"',
  '^(',
  '^)',
  '^<',
  '^>',
  '^|',
])

const E69CMC_WARN = Object.freeze([
  '^&',
  '^^',
])

const E69CMC_ALLOW = Object.freeze([
  'ascii-only',
  'nfkc-normalized',
  'punycode-label',
])

function E69CMCLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function E69CMCIn (list, v) {
  for (const x of list) { if (E69CMCLower(x) === v) return true }
  return false
}

function E69CMCClassify (tok) {
  const v = E69CMCLower(String(tok == null ? '' : tok))
  if (E69CMCIn(E69CMC_BLOCK, v)) return E69CMC_CLASS.BLOCK
  if (E69CMCIn(E69CMC_WARN, v)) return E69CMC_CLASS.WARN
  if (E69CMCIn(E69CMC_ALLOW, v)) return E69CMC_CLASS.ALLOW
  return E69CMC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  E69CMC_CLASS: E69CMC_CLASS,
  E69CMC_BLOCK: E69CMC_BLOCK,
  E69CMC_WARN: E69CMC_WARN,
  E69CMC_ALLOW: E69CMC_ALLOW,
  E69CMCClassify: E69CMCClassify
})
