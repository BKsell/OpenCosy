'use strict'

// errorstackthirdpartycatalogguard.js —— 错误信息外发目录。
//
// 威胁模型：
//   window.onerror/unhandledrejection 把含 URL/堆栈/局部值的错误发到第三方会泄露敏感数据，
//   上报前应脱敏。纯字符查表，不用正则。

const ERL_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const ERL_BLOCK = Object.freeze([
  'onerror-stack-third',
  'unhandledrejection-stack',
  'error.message-url',
  'exception-detail',
])

const ERL_WARN = Object.freeze([
  'source-map-url',
])

const ERL_ALLOW = Object.freeze([
  'same-origin-redacted',
])

function ERLLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function ERLIn (list, v) {
  for (const x of list) { if (ERLLower(x) === v) return true }
  return false
}

function ERLClassify (tok) {
  const v = ERLLower(String(tok == null ? '' : tok).trim())
  if (ERLIn(ERL_BLOCK, v)) return ERL_CLASS.BLOCK
  if (ERLIn(ERL_WARN, v)) return ERL_CLASS.WARN
  if (ERLIn(ERL_ALLOW, v)) return ERL_CLASS.ALLOW
  return ERL_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  ERL_CLASS: ERL_CLASS,
  ERL_BLOCK: ERL_BLOCK,
  ERL_WARN: ERL_WARN,
  ERL_ALLOW: ERL_ALLOW,
  ERLClassify: ERLClassify
})
