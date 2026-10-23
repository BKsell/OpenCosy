'use strict'

// webglparameterfingerprintcatalogguard.js —— WebGL 指纹目录。
//
// 威胁模型：
//   getParameter 读取 UNMASKED_VENDOR/RENDERER、readPixels 构成稳定硬件指纹，
//   应返回泛化值。纯字符查表，不用正则。

const WGF_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WGF_BLOCK = Object.freeze([
  'unmasked_vendor',
  'unmasked_renderer',
  'readpixels-entropy',
  'getextension-debug',
])

const WGF_WARN = Object.freeze([
  'getparameter-generic',
])

const WGF_ALLOW = Object.freeze([
  'generalized-value',
])

function WGFLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WGFIn (list, v) {
  for (const x of list) { if (WGFLower(x) === v) return true }
  return false
}

function WGFClassify (tok) {
  const v = WGFLower(String(tok == null ? '' : tok).trim())
  if (WGFIn(WGF_BLOCK, v)) return WGF_CLASS.BLOCK
  if (WGFIn(WGF_WARN, v)) return WGF_CLASS.WARN
  if (WGFIn(WGF_ALLOW, v)) return WGF_CLASS.ALLOW
  return WGF_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WGF_CLASS: WGF_CLASS,
  WGF_BLOCK: WGF_BLOCK,
  WGF_WARN: WGF_WARN,
  WGF_ALLOW: WGF_ALLOW,
  WGFClassify: WGFClassify
})
