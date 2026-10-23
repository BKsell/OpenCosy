'use strict'

// xsltprocessorsinkcatalogguard.js —— XSLT 处理器 Sink 目录。
//
// 威胁模型：
//   XSLTProcessor.importStylesheet/transformToFragment 处理不可信 XSL 可执行脚本或外发，
//   不应处理外部样式表。纯字符查表，不用正则。

const XSJ_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const XSJ_BLOCK = Object.freeze([
  'xsltprocessor',
  'importstylesheet',
  'transformtofragment',
  'transformtodocument',
])

const XSJ_WARN = Object.freeze([
  'xmlserializer',
])

const XSJ_ALLOW = Object.freeze([
  'static-xslt',
])

function XSJLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function XSJIn (list, v) {
  for (const x of list) { if (XSJLower(x) === v) return true }
  return false
}

function XSJClassify (tok) {
  const v = XSJLower(String(tok == null ? '' : tok).trim())
  if (XSJIn(XSJ_BLOCK, v)) return XSJ_CLASS.BLOCK
  if (XSJIn(XSJ_WARN, v)) return XSJ_CLASS.WARN
  if (XSJIn(XSJ_ALLOW, v)) return XSJ_CLASS.ALLOW
  return XSJ_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  XSJ_CLASS: XSJ_CLASS,
  XSJ_BLOCK: XSJ_BLOCK,
  XSJ_WARN: XSJ_WARN,
  XSJ_ALLOW: XSJ_ALLOW,
  XSJClassify: XSJClassify
})
