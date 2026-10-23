'use strict'

// mixedschemevaluecatalogguard.js —— 页面/子资源协议风险目录。
//
// 威胁模型：
//   https 页面加载 http 子资源是混合内容，file/javascript/data 在安全上下文内更危险。本模块按 scheme 分级，
//   纯字符，不用正则。

const MSV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const MSV_BLOCK = Object.freeze([
  'file',
  'javascript',
  'vbscript',
  'data-text-html',
  'filesystem',
  'netdoc',
])

const MSV_WARN = Object.freeze([
  'http',
  'ws',
  'data',
  'blob',
])

const MSV_ALLOW = Object.freeze([
  'https',
  'wss',
  'about:blank',
  'about:srcdoc',
])

function MSVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function MSVIn (list, v) {
  for (const x of list) { if (MSVLower(x) === v) return true }
  return false
}

function MSVClassify (tok) {
  const v = MSVLower(String(tok == null ? '' : tok).trim())
  if (MSVIn(MSV_BLOCK, v)) return MSV_CLASS.BLOCK
  if (MSVIn(MSV_WARN, v)) return MSV_CLASS.WARN
  if (MSVIn(MSV_ALLOW, v)) return MSV_CLASS.ALLOW
  return MSV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  MSV_CLASS: MSV_CLASS,
  MSV_BLOCK: MSV_BLOCK,
  MSV_WARN: MSV_WARN,
  MSV_ALLOW: MSV_ALLOW,
  MSVClassify: MSVClassify
})
