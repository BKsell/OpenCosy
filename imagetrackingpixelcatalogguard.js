'use strict'

// imagetrackingpixelcatalogguard.js —— 图片像素追踪目录。
//
// 威胁模型：
//   new Image().src 打点/pixel 会携带 Cookie 与 Referer 外泄，
//   应限自有统计并降级来源头。纯字符查表，不用正则。

const IMG_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const IMG_BLOCK = Object.freeze([
  'new-image-src',
  'tracking-pixel',
  'web-bug',
  '1x1-pixel',
])

const IMG_WARN = Object.freeze([
  'img-cross-loading',
])

const IMG_ALLOW = Object.freeze([
  'lazy-own',
])

function IMGLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function IMGIn (list, v) {
  for (const x of list) { if (IMGLower(x) === v) return true }
  return false
}

function IMGClassify (tok) {
  const v = IMGLower(String(tok == null ? '' : tok).trim())
  if (IMGIn(IMG_BLOCK, v)) return IMG_CLASS.BLOCK
  if (IMGIn(IMG_WARN, v)) return IMG_CLASS.WARN
  if (IMGIn(IMG_ALLOW, v)) return IMG_CLASS.ALLOW
  return IMG_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  IMG_CLASS: IMG_CLASS,
  IMG_BLOCK: IMG_BLOCK,
  IMG_WARN: IMG_WARN,
  IMG_ALLOW: IMG_ALLOW,
  IMGClassify: IMGClassify
})
