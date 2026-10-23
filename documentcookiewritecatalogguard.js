'use strict'

// documentcookiewritecatalogguard.js —— document.cookie 写入目录。
//
// 威胁模型：
//   JS 写 document.cookie 默认缺 Secure/SameSite 且可读，
//   敏感 Cookie 应由服务端带全部安全属性下发。纯字符查表，不用正则。

const CKW_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CKW_BLOCK = Object.freeze([
  'document.cookie=',
  'samesite-none',
  'no-secure',
  'no-httponly',
])

const CKW_WARN = Object.freeze([
  'js-readable',
])

const CKW_ALLOW = Object.freeze([
  'secure-httponly',
  'samesite=lax',
])

function CKWLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CKWIn (list, v) {
  for (const x of list) { if (CKWLower(x) === v) return true }
  return false
}

function CKWClassify (tok) {
  const v = CKWLower(String(tok == null ? '' : tok).trim())
  if (CKWIn(CKW_BLOCK, v)) return CKW_CLASS.BLOCK
  if (CKWIn(CKW_WARN, v)) return CKW_CLASS.WARN
  if (CKWIn(CKW_ALLOW, v)) return CKW_CLASS.ALLOW
  return CKW_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CKW_CLASS: CKW_CLASS,
  CKW_BLOCK: CKW_BLOCK,
  CKW_WARN: CKW_WARN,
  CKW_ALLOW: CKW_ALLOW,
  CKWClassify: CKWClassify
})
