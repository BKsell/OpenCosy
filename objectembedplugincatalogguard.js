'use strict'

// objectembedplugincatalogguard.js —— object/embed/applet 插件目录。
//
// 威胁模型：
//   object/embed/param/applet 加载插件或外部数据历史上是 RCE/XSS 面，
//   现代页面应避免使用。纯字符查表，不用正则。

const OES_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const OES_BLOCK = Object.freeze([
  'object',
  'embed',
  'param',
  'applet',
  'pluginspage',
  'codebase',
])

const OES_WARN = Object.freeze([
  'data-cross',
])

const OES_ALLOW = Object.freeze([
  'none',
])

function OESLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function OESIn (list, v) {
  for (const x of list) { if (OESLower(x) === v) return true }
  return false
}

function OESClassify (tok) {
  const v = OESLower(String(tok == null ? '' : tok).trim())
  if (OESIn(OES_BLOCK, v)) return OES_CLASS.BLOCK
  if (OESIn(OES_WARN, v)) return OES_CLASS.WARN
  if (OESIn(OES_ALLOW, v)) return OES_CLASS.ALLOW
  return OES_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  OES_CLASS: OES_CLASS,
  OES_BLOCK: OES_BLOCK,
  OES_WARN: OES_WARN,
  OES_ALLOW: OES_ALLOW,
  OESClassify: OESClassify
})
