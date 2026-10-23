'use strict'

// xcontentoptioncatalogguard.js —— X-Content-Type-Options 取值目录。
//
// 威胁模型：
//   nosniff 关闭 MIME 嗅探是安全值，空/缺失/自定义取值允许浏览器嗅探导致 XSS。纯字符查表，不用正则。

const XCT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const XCT_BLOCK = Object.freeze([
  'none',
  'off',
  'false',
  'sniff',
])

const XCT_WARN = Object.freeze([
  'noopen',
  'noimageindex',
])

const XCT_ALLOW = Object.freeze([
  'nosniff',
])

function XCTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function XCTIn (list, v) {
  for (const x of list) { if (XCTLower(x) === v) return true }
  return false
}

function XCTClassify (tok) {
  const v = XCTLower(String(tok == null ? '' : tok).trim())
  if (XCTIn(XCT_BLOCK, v)) return XCT_CLASS.BLOCK
  if (XCTIn(XCT_WARN, v)) return XCT_CLASS.WARN
  if (XCTIn(XCT_ALLOW, v)) return XCT_CLASS.ALLOW
  return XCT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  XCT_CLASS: XCT_CLASS,
  XCT_BLOCK: XCT_BLOCK,
  XCT_WARN: XCT_WARN,
  XCT_ALLOW: XCT_ALLOW,
  XCTClassify: XCTClassify
})
