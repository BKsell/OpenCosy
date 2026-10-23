'use strict'

// geolocationcontinuoustrackcatalogguard.js —— 定位持续追踪目录。
//
// 威胁模型：
//   watchPosition 持续上报高精度位置比 getCurrentPosition 更敏感，
//   应按需单次、降低精度并要求 https。纯字符查表，不用正则。

const GCT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const GCT_BLOCK = Object.freeze([
  'watchposition',
  'enablehighaccuracy',
  'maximumage-low',
])

const GCT_WARN = Object.freeze([
  'getcurrentposition-nopurpose',
])

const GCT_ALLOW = Object.freeze([
  'https',
  'single-shot',
])

function GCTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function GCTIn (list, v) {
  for (const x of list) { if (GCTLower(x) === v) return true }
  return false
}

function GCTClassify (tok) {
  const v = GCTLower(String(tok == null ? '' : tok).trim())
  if (GCTIn(GCT_BLOCK, v)) return GCT_CLASS.BLOCK
  if (GCTIn(GCT_WARN, v)) return GCT_CLASS.WARN
  if (GCTIn(GCT_ALLOW, v)) return GCT_CLASS.ALLOW
  return GCT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  GCT_CLASS: GCT_CLASS,
  GCT_BLOCK: GCT_BLOCK,
  GCT_WARN: GCT_WARN,
  GCT_ALLOW: GCT_ALLOW,
  GCTClassify: GCTClassify
})
