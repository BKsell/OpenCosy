'use strict'

// cspkeywordcatalogguard.js —— CSP 危险关键字目录。
//
// 威胁模型：
//   'unsafe-inline'/'unsafe-eval'/通配/data:/blob: 让 CSP 失效，'strict-dynamic'/nonce/hash 是强策略。
//   本模块按 CSP 值关键字分级，纯字符，不用正则。

const CSK_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CSK_BLOCK = Object.freeze([
  '\'unsafe-inline\'',
  '\'unsafe-eval\'',
  '\'unsafe-hashes\'',
  '*',
  'data:',
  'blob:',
  'filesystem:',
  'https://*',
  'http://*',
  '\'unsafe-allow-redirects\'',
])

const CSK_WARN = Object.freeze([
  '\'self\'',
  'http://',
  '\'wasm-unsafe-eval\'',
  '\'report-sample\'',
])

const CSK_ALLOW = Object.freeze([
  '\'none\'',
  '\'strict-dynamic\'',
  '\'nonce-',
  '\'sha256-',
  '\'sha384-',
  '\'sha512-',
  'https:',
])

function CSKLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CSKIn (list, v) {
  for (const x of list) { if (CSKLower(x) === v) return true }
  return false
}

function CSKClassify (tok) {
  const v = CSKLower(String(tok == null ? '' : tok).trim())
  if (CSKIn(CSK_BLOCK, v)) return CSK_CLASS.BLOCK
  if (CSKIn(CSK_WARN, v)) return CSK_CLASS.WARN
  if (CSKIn(CSK_ALLOW, v)) return CSK_CLASS.ALLOW
  return CSK_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CSK_CLASS: CSK_CLASS,
  CSK_BLOCK: CSK_BLOCK,
  CSK_WARN: CSK_WARN,
  CSK_ALLOW: CSK_ALLOW,
  CSKClassify: CSKClassify
})
