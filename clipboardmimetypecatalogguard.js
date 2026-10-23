'use strict'

// clipboardmimetypecatalogguard.js —— 剪贴板危险 MIME/数据类型目录。
//
// 威胁模型：
//   剪贴板写入 text/html 含脚本、image/svg+xml、自定义富文本类型可在粘贴面形成 XSS。纯字符查表，不用正则。

const CLM_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CLM_BLOCK = Object.freeze([
  'text/html',
  'image/svg+xml',
  'application/xhtml+xml',
  'text/xml',
  'application/xml',
  'multipart/x-mixed-replace',
])

const CLM_WARN = Object.freeze([
  'text/rtf',
  'application/rtf',
  'image/html',
  'text/x-markdown',
  'application/x-moz-file',
  'Files',
  'application/x-vnd.openxmlformats-officedocument',
  'application/msword',
  'application/vnd.ms-excel',
  'application/x-java-jnlp-file',
  'application/x-msdownload',
  'text/scriptlet',
])

const CLM_ALLOW = Object.freeze([
  'text/plain',
  'text/plain;charset=utf-8',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'application/json',
  'text/uri-list',
])

function CLMLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CLMIn (list, v) {
  for (const x of list) { if (CLMLower(x) === v) return true }
  return false
}

function CLMClassify (tok) {
  const v = CLMLower(String(tok == null ? '' : tok).trim())
  if (CLMIn(CLM_BLOCK, v)) return CLM_CLASS.BLOCK
  if (CLMIn(CLM_WARN, v)) return CLM_CLASS.WARN
  if (CLMIn(CLM_ALLOW, v)) return CLM_CLASS.ALLOW
  return CLM_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CLM_CLASS: CLM_CLASS,
  CLM_BLOCK: CLM_BLOCK,
  CLM_WARN: CLM_WARN,
  CLM_ALLOW: CLM_ALLOW,
  CLMClassify: CLMClassify
})
