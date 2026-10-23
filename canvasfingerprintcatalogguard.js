'use strict'

// canvasfingerprintcatalogguard.js —— Canvas 指纹 Sink 目录。
//
// 威胁模型：
//   getImageData/toDataURL + 字体渲染差异是经典跨站指纹，
//   隐私模式应加噪或拒绝。纯字符查表，不用正则。

const CFP_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CFP_BLOCK = Object.freeze([
  'getimagedata-entropy',
  'todataurl-fingerprint',
  'measuretext-canvas',
  'webgl-readback',
])

const CFP_WARN = Object.freeze([
  'toblob-entropy',
])

const CFP_ALLOW = Object.freeze([
  'noise',
  'blocked',
])

function CFPLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CFPIn (list, v) {
  for (const x of list) { if (CFPLower(x) === v) return true }
  return false
}

function CFPClassify (tok) {
  const v = CFPLower(String(tok == null ? '' : tok).trim())
  if (CFPIn(CFP_BLOCK, v)) return CFP_CLASS.BLOCK
  if (CFPIn(CFP_WARN, v)) return CFP_CLASS.WARN
  if (CFPIn(CFP_ALLOW, v)) return CFP_CLASS.ALLOW
  return CFP_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CFP_CLASS: CFP_CLASS,
  CFP_BLOCK: CFP_BLOCK,
  CFP_WARN: CFP_WARN,
  CFP_ALLOW: CFP_ALLOW,
  CFPClassify: CFPClassify
})
