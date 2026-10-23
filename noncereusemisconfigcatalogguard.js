'use strict'

// noncereusemisconfigcatalogguard.js —— 脚本 nonce 复用/缺失目录。
//
// 威胁模型：
//   nonce 跨响应复用、长期静态或与 unsafe-inline 并存等于没有 nonce，
//   应每响应随机一次性。纯字符查表，不用正则。

const NCE_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const NCE_BLOCK = Object.freeze([
  'nonce-reused',
  'static-nonce',
  'unsafe-inline-with-nonce',
  'nonce-missing',
])

const NCE_WARN = Object.freeze([
  'long-lived-nonce',
])

const NCE_ALLOW = Object.freeze([
  'per-response-random',
])

function NCELower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function NCEIn (list, v) {
  for (const x of list) { if (NCELower(x) === v) return true }
  return false
}

function NCEClassify (tok) {
  const v = NCELower(String(tok == null ? '' : tok).trim())
  if (NCEIn(NCE_BLOCK, v)) return NCE_CLASS.BLOCK
  if (NCEIn(NCE_WARN, v)) return NCE_CLASS.WARN
  if (NCEIn(NCE_ALLOW, v)) return NCE_CLASS.ALLOW
  return NCE_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  NCE_CLASS: NCE_CLASS,
  NCE_BLOCK: NCE_BLOCK,
  NCE_WARN: NCE_WARN,
  NCE_ALLOW: NCE_ALLOW,
  NCEClassify: NCEClassify
})
