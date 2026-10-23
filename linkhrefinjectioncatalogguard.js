'use strict'

// linkhrefinjectioncatalogguard.js —— link href 注入目录。
//
// 威胁模型：
//   link 的 prefetch/prerender/import/icon 指向不可信 href 可泄露凭据或加载恶意内容，
//   样式表也应限同源。纯字符查表，不用正则。

const LHI_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const LHI_BLOCK = Object.freeze([
  'prefetch',
  'prerender',
  'import',
  'icon-data',
  'stylesheet-cross',
])

const LHI_WARN = Object.freeze([
  'preload-cross',
])

const LHI_ALLOW = Object.freeze([
  'same-origin-css',
])

function LHILower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function LHIIn (list, v) {
  for (const x of list) { if (LHILower(x) === v) return true }
  return false
}

function LHIClassify (tok) {
  const v = LHILower(String(tok == null ? '' : tok).trim())
  if (LHIIn(LHI_BLOCK, v)) return LHI_CLASS.BLOCK
  if (LHIIn(LHI_WARN, v)) return LHI_CLASS.WARN
  if (LHIIn(LHI_ALLOW, v)) return LHI_CLASS.ALLOW
  return LHI_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  LHI_CLASS: LHI_CLASS,
  LHI_BLOCK: LHI_BLOCK,
  LHI_WARN: LHI_WARN,
  LHI_ALLOW: LHI_ALLOW,
  LHIClassify: LHIClassify
})
