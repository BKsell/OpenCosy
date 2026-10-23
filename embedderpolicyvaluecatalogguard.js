'use strict'

// embedderpolicyvaluecatalogguard.js —— COEP/CORP 嵌入策略取值目录。
//
// 威胁模型：
//   require-corp 强制、credentialless 宽松、unsafe-none 关闭隔离，按跨源嵌入资源分级。纯字符查表，不用正则。

const EPV_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const EPV_BLOCK = Object.freeze([
  'unsafe-none',
])

const EPV_WARN = Object.freeze([
  'credentialless',
  'cross-origin',
])

const EPV_ALLOW = Object.freeze([
  'require-corp',
  'same-origin',
  'same-site',
])

function EPVLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function EPVIn (list, v) {
  for (const x of list) { if (EPVLower(x) === v) return true }
  return false
}

function EPVClassify (tok) {
  const v = EPVLower(String(tok == null ? '' : tok).trim())
  if (EPVIn(EPV_BLOCK, v)) return EPV_CLASS.BLOCK
  if (EPVIn(EPV_WARN, v)) return EPV_CLASS.WARN
  if (EPVIn(EPV_ALLOW, v)) return EPV_CLASS.ALLOW
  return EPV_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  EPV_CLASS: EPV_CLASS,
  EPV_BLOCK: EPV_BLOCK,
  EPV_WARN: EPV_WARN,
  EPV_ALLOW: EPV_ALLOW,
  EPVClassify: EPVClassify
})
