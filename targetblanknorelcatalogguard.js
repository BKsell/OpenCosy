'use strict'

// targetblanknorelcatalogguard.js —— target=_blank 反向标签目录。
//
// 威胁模型：
//   target=_blank 无 rel=noopener 允许新页面通过 window.opener 操控原页(tabnabbing)，
//   应带 noopener/noreferrer。纯字符查表，不用正则。

const TBR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const TBR_BLOCK = Object.freeze([
  'target=_blank-no-rel',
  'window.open-noopener',
  '_blank',
])

const TBR_WARN = Object.freeze([
  '_parent',
])

const TBR_ALLOW = Object.freeze([
  'noopener',
  'noreferrer',
])

function TBRLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function TBRIn (list, v) {
  for (const x of list) { if (TBRLower(x) === v) return true }
  return false
}

function TBRClassify (tok) {
  const v = TBRLower(String(tok == null ? '' : tok).trim())
  if (TBRIn(TBR_BLOCK, v)) return TBR_CLASS.BLOCK
  if (TBRIn(TBR_WARN, v)) return TBR_CLASS.WARN
  if (TBRIn(TBR_ALLOW, v)) return TBR_CLASS.ALLOW
  return TBR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  TBR_CLASS: TBR_CLASS,
  TBR_BLOCK: TBR_BLOCK,
  TBR_WARN: TBR_WARN,
  TBR_ALLOW: TBR_ALLOW,
  TBRClassify: TBRClassify
})
