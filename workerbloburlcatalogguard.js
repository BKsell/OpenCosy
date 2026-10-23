'use strict'

// workerbloburlcatalogguard.js —— Worker 动态来源目录。
//
// 威胁模型：
//   new Worker(blob:/data: URL) 或跨源 worker、importScripts 外域会扩大脚本执行面，
//   应同源静态脚本。纯字符查表，不用正则。

const WKS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WKS_BLOCK = Object.freeze([
  'worker-blob',
  'worker-data',
  'importscripts-cross',
  'worker-cross-origin',
])

const WKS_WARN = Object.freeze([
  'module-worker',
])

const WKS_ALLOW = Object.freeze([
  'same-origin-worker',
])

function WKSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WKSIn (list, v) {
  for (const x of list) { if (WKSLower(x) === v) return true }
  return false
}

function WKSClassify (tok) {
  const v = WKSLower(String(tok == null ? '' : tok).trim())
  if (WKSIn(WKS_BLOCK, v)) return WKS_CLASS.BLOCK
  if (WKSIn(WKS_WARN, v)) return WKS_CLASS.WARN
  if (WKSIn(WKS_ALLOW, v)) return WKS_CLASS.ALLOW
  return WKS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WKS_CLASS: WKS_CLASS,
  WKS_BLOCK: WKS_BLOCK,
  WKS_WARN: WKS_WARN,
  WKS_ALLOW: WKS_ALLOW,
  WKSClassify: WKSClassify
})
