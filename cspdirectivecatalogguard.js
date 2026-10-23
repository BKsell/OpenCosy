'use strict'

// cspdirectivecatalogguard.js —— CSP 指令名风险目录。
//
// 威胁模型：
//   report-uri 已废弃，frame-ancestors/object-base/default-src 是关键收口指令。本模块按指令名分级，
//   纯字符，不用正则。

const CSD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CSD_BLOCK = Object.freeze([
  'report-uri',
  'plugin-types',
  'referrer-no-directive',
])

const CSD_WARN = Object.freeze([
  'script-src-attr',
  'script-src-elem',
  'style-src-attr',
  'reflected-xss',
  'block-all-mixed-content',
])

const CSD_ALLOW = Object.freeze([
  'default-src',
  'script-src',
  'style-src',
  'img-src',
  'connect-src',
  'font-src',
  'object-src',
  'base-uri',
  'frame-ancestors',
  'form-action',
  'navigate-to',
  'require-trusted-types-for',
  'report-to',
  'upgrade-insecure-requests',
  'sandbox',
  'worker-src',
  'media-src',
  'manifest-src',
])

function CSDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CSDIn (list, v) {
  for (const x of list) { if (CSDLower(x) === v) return true }
  return false
}

function CSDClassify (tok) {
  const v = CSDLower(String(tok == null ? '' : tok).trim())
  if (CSDIn(CSD_BLOCK, v)) return CSD_CLASS.BLOCK
  if (CSDIn(CSD_WARN, v)) return CSD_CLASS.WARN
  if (CSDIn(CSD_ALLOW, v)) return CSD_CLASS.ALLOW
  return CSD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CSD_CLASS: CSD_CLASS,
  CSD_BLOCK: CSD_BLOCK,
  CSD_WARN: CSD_WARN,
  CSD_ALLOW: CSD_ALLOW,
  CSDClassify: CSDClassify
})
