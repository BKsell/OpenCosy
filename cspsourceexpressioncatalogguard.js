'use strict'

// cspsourceexpressioncatalogguard.js —— CSP source-expression 风险目录。
//
// 威胁模型：
//   CSP 中的 *、data:、unsafe-inline、unsafe-eval、https: 过宽源削弱防护，'self'/nonce/hash 严格源放行。纯字符查表，不用正则。

const CSE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CSE_BLOCK = Object.freeze([
  '*',
  '\'unsafe-inline\'',
  '\'unsafe-eval\'',
  '\'unsafe-hashes\'',
  'data:',
  'http:',
  'https:',
  'blob:',
  'filesystem:',
])

const CSE_WARN = Object.freeze([
  '\'report-sample\'',
  '\'wasm-unsafe-eval\'',
  'mediastream:',
  'ws:',
  'wss:',
  'nonce-',
  'sha256-',
  'sha384-',
  'sha512-',
])

const CSE_ALLOW = Object.freeze([
  '\'none\'',
  '\'self\'',
  '\'strict-dynamic\'',
  'example.com',
  'https://cdn.example.com',
  'https://api.example.com',
  '\'nonce-r4nd0m\'',
  '\'sha256-base64hash\'',
])

function CSELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CSEIn (list, v) {
  for (const x of list) { if (CSELower(x) === v) return true }
  return false
}

function CSEClassify (tok) {
  const v = CSELower(String(tok == null ? '' : tok).trim())
  if (CSEIn(CSE_BLOCK, v)) return CSE_CLASS.BLOCK
  if (CSEIn(CSE_WARN, v)) return CSE_CLASS.WARN
  if (CSEIn(CSE_ALLOW, v)) return CSE_CLASS.ALLOW
  return CSE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CSE_CLASS: CSE_CLASS,
  CSE_BLOCK: CSE_BLOCK,
  CSE_WARN: CSE_WARN,
  CSE_ALLOW: CSE_ALLOW,
  CSEClassify: CSEClassify
})
