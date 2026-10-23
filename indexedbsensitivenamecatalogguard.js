'use strict'

// indexedbsensitivenamecatalogguard.js —— IndexedDB 敏感库/对象仓目录。
//
// 威胁模型：
//   IndexedDB 持久化保存密钥/密码/令牌可被 XSS 读取，
//   不应存高敏数据。纯字符查表，不用正则。

const IDS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IDS_BLOCK = Object.freeze([
  'secret-store',
  'keypath-password',
  'token-index',
  'vault-db',
])

const IDS_WARN = Object.freeze([
  'index-token',
])

const IDS_ALLOW = Object.freeze([
  'non-sensitive',
])

function IDSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IDSIn (list, v) {
  for (const x of list) { if (IDSLower(x) === v) return true }
  return false
}

function IDSClassify (tok) {
  const v = IDSLower(String(tok == null ? '' : tok).trim())
  if (IDSIn(IDS_BLOCK, v)) return IDS_CLASS.BLOCK
  if (IDSIn(IDS_WARN, v)) return IDS_CLASS.WARN
  if (IDSIn(IDS_ALLOW, v)) return IDS_CLASS.ALLOW
  return IDS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IDS_CLASS: IDS_CLASS,
  IDS_BLOCK: IDS_BLOCK,
  IDS_WARN: IDS_WARN,
  IDS_ALLOW: IDS_ALLOW,
  IDSClassify: IDSClassify
})
