'use strict'

// cspreporturiinsecurecatalogguard.js —— CSP 报告端点安全目录。
//
// 威胁模型：
//   report-uri 指向 http 或 report-to 任意端点会把违规页面 URL/片段发到不可信处，
//   应 https 受控端点。纯字符查表，不用正则。

const CRJ_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CRJ_BLOCK = Object.freeze([
  'report-uri-http',
  'report-to-*',
  'report-uri-relative-abuse',
])

const CRJ_WARN = Object.freeze([
  'report-uri-legacy',
])

const CRJ_ALLOW = Object.freeze([
  'report-to-https',
])

function CRJLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CRJIn (list, v) {
  for (const x of list) { if (CRJLower(x) === v) return true }
  return false
}

function CRJClassify (tok) {
  const v = CRJLower(String(tok == null ? '' : tok).trim())
  if (CRJIn(CRJ_BLOCK, v)) return CRJ_CLASS.BLOCK
  if (CRJIn(CRJ_WARN, v)) return CRJ_CLASS.WARN
  if (CRJIn(CRJ_ALLOW, v)) return CRJ_CLASS.ALLOW
  return CRJ_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CRJ_CLASS: CRJ_CLASS,
  CRJ_BLOCK: CRJ_BLOCK,
  CRJ_WARN: CRJ_WARN,
  CRJ_ALLOW: CRJ_ALLOW,
  CRJClassify: CRJClassify
})
