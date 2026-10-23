'use strict'

// locationnavigationsinkcatalogguard.js —— JS 导航 Sink 目录。
//
// 威胁模型：
//   对 location.href/assign/replace/window.open 赋不可信 URL 可 open-redirect 或执行脚本，
//   应走源协议白名单。纯字符查表，不用正则。

const LAS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const LAS_BLOCK = Object.freeze([
  'location.href',
  'assign',
  'replace',
  'window.open',
  'document.url',
])

const LAS_WARN = Object.freeze([
  'location.assign-input',
])

const LAS_ALLOW = Object.freeze([
  'origin-allowlist',
])

function LASLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function LASIn (list, v) {
  for (const x of list) { if (LASLower(x) === v) return true }
  return false
}

function LASClassify (tok) {
  const v = LASLower(String(tok == null ? '' : tok).trim())
  if (LASIn(LAS_BLOCK, v)) return LAS_CLASS.BLOCK
  if (LASIn(LAS_WARN, v)) return LAS_CLASS.WARN
  if (LASIn(LAS_ALLOW, v)) return LAS_CLASS.ALLOW
  return LAS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  LAS_CLASS: LAS_CLASS,
  LAS_BLOCK: LAS_BLOCK,
  LAS_WARN: LAS_WARN,
  LAS_ALLOW: LAS_ALLOW,
  LASClassify: LASClassify
})
