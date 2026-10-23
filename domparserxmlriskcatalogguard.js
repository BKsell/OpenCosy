'use strict'

// domparserxmlriskcatalogguard.js —— DOMParser 危险类型目录。
//
// 威胁模型：
//   DOMParser 解析 text/html/image/svg+xml 不可信内容会执行脚本，
//   外部实体 XML 也有 XXE 风险，应只解析 application/json。纯字符查表，不用正则。

const DPX_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DPX_BLOCK = Object.freeze([
  'image/svg+xml',
  'text/html',
  'text/xml',
])

const DPX_WARN = Object.freeze([
  'application/xml',
  'application/xhtml+xml',
])

const DPX_ALLOW = Object.freeze([
  'application/json',
])

function DPXLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DPXIn (list, v) {
  for (const x of list) { if (DPXLower(x) === v) return true }
  return false
}

function DPXClassify (tok) {
  const v = DPXLower(String(tok == null ? '' : tok).trim())
  if (DPXIn(DPX_BLOCK, v)) return DPX_CLASS.BLOCK
  if (DPXIn(DPX_WARN, v)) return DPX_CLASS.WARN
  if (DPXIn(DPX_ALLOW, v)) return DPX_CLASS.ALLOW
  return DPX_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DPX_CLASS: DPX_CLASS,
  DPX_BLOCK: DPX_BLOCK,
  DPX_WARN: DPX_WARN,
  DPX_ALLOW: DPX_ALLOW,
  DPXClassify: DPXClassify
})
