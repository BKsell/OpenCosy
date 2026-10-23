'use strict'

// cspreportkeycatalogguard.js —— CSP 违规报告字段风险目录。
//
// 威胁模型：
//   script-sample/original-policy 可能携带敏感代码片段，document-uri/source-file/referrer 含敏感页面 URL，上报前需脱敏。纯字符查表，不用正则。

const CPR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CPR_BLOCK = Object.freeze([
  'script-sample',
  'original-policy',
])

const CPR_WARN = Object.freeze([
  'document-uri',
  'blocked-uri',
  'referrer',
  'source-file',
])

const CPR_ALLOW = Object.freeze([
  'violated-directive',
  'effective-directive',
  'disposition',
  'status-code',
  'line-number',
  'column-number',
])

function CPRLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CPRIn (list, v) {
  for (const x of list) { if (CPRLower(x) === v) return true }
  return false
}

function CPRClassify (tok) {
  const v = CPRLower(String(tok == null ? '' : tok).trim())
  if (CPRIn(CPR_BLOCK, v)) return CPR_CLASS.BLOCK
  if (CPRIn(CPR_WARN, v)) return CPR_CLASS.WARN
  if (CPRIn(CPR_ALLOW, v)) return CPR_CLASS.ALLOW
  return CPR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CPR_CLASS: CPR_CLASS,
  CPR_BLOCK: CPR_BLOCK,
  CPR_WARN: CPR_WARN,
  CPR_ALLOW: CPR_ALLOW,
  CPRClassify: CPRClassify
})
