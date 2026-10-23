'use strict'

// xframevaluecatalogguard.js —— X-Frame-Options 取值目录。
//
// 威胁模型：
//   ALLOW-FROM 已废弃且不可靠，DENY/SAMEORIGIN 才提供点击劫持防护。本模块按取值分级，纯字符，不用正则。

const XFV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const XFV_BLOCK = Object.freeze([
  'ALLOW-FROM',
  'ALLOWALL',
  'empty-xfo-policy',
])

const XFV_WARN = Object.freeze([
  'SAMEORIGIN-LAX',
  'allow-all',
])

const XFV_ALLOW = Object.freeze([
  'DENY',
  'SAMEORIGIN',
])

function XFVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function XFVIn (list, v) {
  for (const x of list) { if (XFVLower(x) === v) return true }
  return false
}

function XFVClassify (tok) {
  const v = XFVLower(String(tok == null ? '' : tok).trim())
  if (XFVIn(XFV_BLOCK, v)) return XFV_CLASS.BLOCK
  if (XFVIn(XFV_WARN, v)) return XFV_CLASS.WARN
  if (XFVIn(XFV_ALLOW, v)) return XFV_CLASS.ALLOW
  return XFV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  XFV_CLASS: XFV_CLASS,
  XFV_BLOCK: XFV_BLOCK,
  XFV_WARN: XFV_WARN,
  XFV_ALLOW: XFV_ALLOW,
  XFVClassify: XFVClassify
})
