'use strict'

// cspdirectiveweakvaluecatalogguard.js —— CSP 指令宽松取值目录。
//
// 威胁模型：
//   default-src *、object-src 未限制、base-uri 缺失均可被利用，
//   应显式 self/nonce 并限制 object-src/base-uri。纯字符查表，不用正则。

const CDV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CDV_BLOCK = Object.freeze([
  'default-src *',
  'object-src *',
  'base-uri *',
  'unsafe-inline',
  'unsafe-eval',
])

const CDV_WARN = Object.freeze([
  'https-only-src',
])

const CDV_ALLOW = Object.freeze([
  'self',
  'nonce',
  'object-src-none',
])

function CDVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CDVIn (list, v) {
  for (const x of list) { if (CDVLower(x) === v) return true }
  return false
}

function CDVClassify (tok) {
  const v = CDVLower(String(tok == null ? '' : tok).trim())
  if (CDVIn(CDV_BLOCK, v)) return CDV_CLASS.BLOCK
  if (CDVIn(CDV_WARN, v)) return CDV_CLASS.WARN
  if (CDVIn(CDV_ALLOW, v)) return CDV_CLASS.ALLOW
  return CDV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CDV_CLASS: CDV_CLASS,
  CDV_BLOCK: CDV_BLOCK,
  CDV_WARN: CDV_WARN,
  CDV_ALLOW: CDV_ALLOW,
  CDVClassify: CDVClassify
})
