'use strict'

// referrervaluecatalogguard.js —— Referrer-Policy 取值目录。
//
// 威胁模型：
//   unsafe-url 始终泄露完整 URL（含令牌查询参数），no-referrer/strict-origin 系列更安全。本模块按取值分级，
//   纯字符，不用正则。

const RVG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const RVG_BLOCK = Object.freeze([
  'unsafe-url',
  'empty-referrer-policy',
  'no-referrer-when-downgrade-insecure',
])

const RVG_WARN = Object.freeze([
  'origin',
  'origin-when-cross-origin',
  'no-referrer-when-downgrade',
  'same-origin',
])

const RVG_ALLOW = Object.freeze([
  'no-referrer',
  'same-origin-strict',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'never',
])

function RVGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function RVGIn (list, v) {
  for (const x of list) { if (RVGLower(x) === v) return true }
  return false
}

function RVGClassify (tok) {
  const v = RVGLower(String(tok == null ? '' : tok).trim())
  if (RVGIn(RVG_BLOCK, v)) return RVG_CLASS.BLOCK
  if (RVGIn(RVG_WARN, v)) return RVG_CLASS.WARN
  if (RVGIn(RVG_ALLOW, v)) return RVG_CLASS.ALLOW
  return RVG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  RVG_CLASS: RVG_CLASS,
  RVG_BLOCK: RVG_BLOCK,
  RVG_WARN: RVG_WARN,
  RVG_ALLOW: RVG_ALLOW,
  RVGClassify: RVGClassify
})
