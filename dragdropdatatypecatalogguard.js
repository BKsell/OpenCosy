'use strict'

// dragdropdatatypecatalogguard.js —— 拖放 DataTransfer 危险类型目录。
//
// 威胁模型：
//   拖放 text/uri-list、DownloadURL、Files、text/html 进入应用需校验，文件拖放配合路径可写盘。纯字符查表，不用正则。

const DDT_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DDT_BLOCK = Object.freeze([
  'DownloadURL',
  'application/x-moz-file',
  'text/html',
  'image/svg+xml',
])

const DDT_WARN = Object.freeze([
  'Files',
  'text/uri-list',
  'application/x-moz-file-promise',
  'application/x-moz-file-promise-url',
  'application/x-moz-file-promise-dest-filename',
  'text/x-moz-url',
  'text/x-moz-url-data',
  'text/x-moz-url-desc',
  'application/x-cut-data',
  'application/x-win-bitmap',
  'CF_HDROP',
  'CFSTR_FILECONTENTS',
  'CFSTR_FILEDESCRIPTOR',
])

const DDT_ALLOW = Object.freeze([
  'text/plain',
  'text/plain;charset=utf-8',
  'image/png',
  'image/jpeg',
  'application/json',
])

function DDTLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DDTIn (list, v) {
  for (const x of list) { if (DDTLower(x) === v) return true }
  return false
}

function DDTClassify (tok) {
  const v = DDTLower(String(tok == null ? '' : tok).trim())
  if (DDTIn(DDT_BLOCK, v)) return DDT_CLASS.BLOCK
  if (DDTIn(DDT_WARN, v)) return DDT_CLASS.WARN
  if (DDTIn(DDT_ALLOW, v)) return DDT_CLASS.ALLOW
  return DDT_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DDT_CLASS: DDT_CLASS,
  DDT_BLOCK: DDT_BLOCK,
  DDT_WARN: DDT_WARN,
  DDT_ALLOW: DDT_ALLOW,
  DDTClassify: DDTClassify
})
