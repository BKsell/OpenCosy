'use strict'

// downloadattrcrossorigincatalogguard.js —— download 跨源下载目录。
//
// 威胁模型：
//   a[download] 配跨源 URL/data: 会忽略文件名或下载可执行内容，
//   应同源并校验类型。纯字符查表，不用正则。

const DLA_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const DLA_BLOCK = Object.freeze([
  'download-crossorigin',
  'data-download',
  'blob-cross',
])

const DLA_WARN = Object.freeze([
  'download-named',
])

const DLA_ALLOW = Object.freeze([
  'same-origin-download',
])

function DLALower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function DLAIn (list, v) {
  for (const x of list) { if (DLALower(x) === v) return true }
  return false
}

function DLAClassify (tok) {
  const v = DLALower(String(tok == null ? '' : tok).trim())
  if (DLAIn(DLA_BLOCK, v)) return DLA_CLASS.BLOCK
  if (DLAIn(DLA_WARN, v)) return DLA_CLASS.WARN
  if (DLAIn(DLA_ALLOW, v)) return DLA_CLASS.ALLOW
  return DLA_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  DLA_CLASS: DLA_CLASS,
  DLA_BLOCK: DLA_BLOCK,
  DLA_WARN: DLA_WARN,
  DLA_ALLOW: DLA_ALLOW,
  DLAClassify: DLAClassify
})
