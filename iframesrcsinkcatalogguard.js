'use strict'

// iframesrcsinkcatalogguard.js —— iframe/frame 注入目录。
//
// 威胁模型：
//   iframe src=javascript:、srcdoc 或 allow 属性可执行脚本并绕过隔离，
//   object/embed data 同理，应 sandbox 后固定源。纯字符查表，不用正则。

const IFS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IFS_BLOCK = Object.freeze([
  'iframe-javascript',
  'srcdoc',
  'allow',
  'frame src',
  'object data',
  'embed src',
])

const IFS_WARN = Object.freeze([
  'sandbox-flags-loose',
])

const IFS_ALLOW = Object.freeze([
  'sandboxed-https',
])

function IFSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IFSIn (list, v) {
  for (const x of list) { if (IFSLower(x) === v) return true }
  return false
}

function IFSClassify (tok) {
  const v = IFSLower(String(tok == null ? '' : tok).trim())
  if (IFSIn(IFS_BLOCK, v)) return IFS_CLASS.BLOCK
  if (IFSIn(IFS_WARN, v)) return IFS_CLASS.WARN
  if (IFSIn(IFS_ALLOW, v)) return IFS_CLASS.ALLOW
  return IFS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IFS_CLASS: IFS_CLASS,
  IFS_BLOCK: IFS_BLOCK,
  IFS_WARN: IFS_WARN,
  IFS_ALLOW: IFS_ALLOW,
  IFSClassify: IFSClassify
})
