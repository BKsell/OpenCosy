'use strict'

// fetchmetadatavaluecatalogguard.js —— Fetch Metadata 请求隔离取值目录。
//
// 威胁模型：
//   Sec-Fetch-Site=cross-site、Mode=no-cors/websocket、Dest=document/object/embed 用于隔离判定，同站/同源值放行。纯字符查表，不用正则。

const FMD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const FMD_BLOCK = Object.freeze([
  'cross-site',
  'websocket',
  'no-cors',
  'object',
  'embed',
])

const FMD_WARN = Object.freeze([
  'none',
  'navigate',
  'nested-navigate',
  'cors',
  'cors-forced',
  'document',
  'iframe',
  'serviceworker',
  'sharedworker',
  'worker',
  'manifest',
])

const FMD_ALLOW = Object.freeze([
  'same-origin',
  'same-site',
  'empty',
  'image',
  'font',
  'script',
  'style',
  'audio',
  'video',
  'track',
])

function FMDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FMDIn (list, v) {
  for (const x of list) { if (FMDLower(x) === v) return true }
  return false
}

function FMDClassify (tok) {
  const v = FMDLower(String(tok == null ? '' : tok).trim())
  if (FMDIn(FMD_BLOCK, v)) return FMD_CLASS.BLOCK
  if (FMDIn(FMD_WARN, v)) return FMD_CLASS.WARN
  if (FMDIn(FMD_ALLOW, v)) return FMD_CLASS.ALLOW
  return FMD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  FMD_CLASS: FMD_CLASS,
  FMD_BLOCK: FMD_BLOCK,
  FMD_WARN: FMD_WARN,
  FMD_ALLOW: FMD_ALLOW,
  FMDClassify: FMDClassify
})
