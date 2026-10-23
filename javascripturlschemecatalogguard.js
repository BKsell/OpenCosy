'use strict'

// javascripturlschemecatalogguard.js —— javascript:/data: URL 目录。
//
// 威胁模型：
//   javascript:/vbscript: 与 data:text/html 进入导航/资源属性即脚本执行，
//   应只允许 http/https 并按源校验。纯字符查表，不用正则。

const JSU_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const JSU_BLOCK = Object.freeze([
  'javascript:',
  'vbscript:',
  'data:text/html',
])

const JSU_WARN = Object.freeze([
  'data:image',
  'blob:',
])

const JSU_ALLOW = Object.freeze([
  'http://',
  'https://',
])

function JSULower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function JSUIn (list, v) {
  for (const x of list) { if (JSULower(x) === v) return true }
  return false
}

function JSUClassify (tok) {
  const v = JSULower(String(tok == null ? '' : tok).trim())
  if (JSUIn(JSU_BLOCK, v)) return JSU_CLASS.BLOCK
  if (JSUIn(JSU_WARN, v)) return JSU_CLASS.WARN
  if (JSUIn(JSU_ALLOW, v)) return JSU_CLASS.ALLOW
  return JSU_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  JSU_CLASS: JSU_CLASS,
  JSU_BLOCK: JSU_BLOCK,
  JSU_WARN: JSU_WARN,
  JSU_ALLOW: JSU_ALLOW,
  JSUClassify: JSUClassify
})
