'use strict'

// storagesensitivenamecatalogguard.js —— Web Storage 敏感键名目录。
//
// 威胁模型：
//   localStorage/sessionStorage 存 token/password/jwt 会被 XSS 直接读取且长期留存，
//   敏感凭据应放 HttpOnly Cookie/内存。纯字符查表，不用正则。

const STN_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const STN_BLOCK = Object.freeze([
  'token',
  'password',
  'jwt',
  'secret',
  'creditcard',
  'session',
])

const STN_WARN = Object.freeze([
  'sessionstorage-token',
])

const STN_ALLOW = Object.freeze([
  'memory',
  'httponly-cookie',
])

function STNLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function STNIn (list, v) {
  for (const x of list) { if (STNLower(x) === v) return true }
  return false
}

function STNClassify (tok) {
  const v = STNLower(String(tok == null ? '' : tok).trim())
  if (STNIn(STN_BLOCK, v)) return STN_CLASS.BLOCK
  if (STNIn(STN_WARN, v)) return STN_CLASS.WARN
  if (STNIn(STN_ALLOW, v)) return STN_CLASS.ALLOW
  return STN_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  STN_CLASS: STN_CLASS,
  STN_BLOCK: STN_BLOCK,
  STN_WARN: STN_WARN,
  STN_ALLOW: STN_ALLOW,
  STNClassify: STNClassify
})
