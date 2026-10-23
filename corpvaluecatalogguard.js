'use strict'

// corpvaluecatalogguard.js —— CORP 取值风险目录。
//
// 威胁模型：
//   私有资源 cross-origin 等同公开，same-site 弱于 same-origin。本模块按 Cross-Origin-Resource-Policy
//   取值与资源敏感度分级，纯字符，不用正则。

const CRV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CRV_BLOCK = Object.freeze([
  'cross-origin-on-private',
  'empty-corp-on-private',
])

const CRV_WARN = Object.freeze([
  'cross-origin',
  'same-site-on-strict',
])

const CRV_ALLOW = Object.freeze([
  'same-origin',
  'same-site',
  'cross-origin-on-public',
])

function CRVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CRVIn (list, v) {
  for (const x of list) { if (CRVLower(x) === v) return true }
  return false
}

function CRVClassify (tok) {
  const v = CRVLower(String(tok == null ? '' : tok).trim())
  if (CRVIn(CRV_BLOCK, v)) return CRV_CLASS.BLOCK
  if (CRVIn(CRV_WARN, v)) return CRV_CLASS.WARN
  if (CRVIn(CRV_ALLOW, v)) return CRV_CLASS.ALLOW
  return CRV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CRV_CLASS: CRV_CLASS,
  CRV_BLOCK: CRV_BLOCK,
  CRV_WARN: CRV_WARN,
  CRV_ALLOW: CRV_ALLOW,
  CRVClassify: CRVClassify
})
