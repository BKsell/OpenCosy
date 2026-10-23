'use strict'

// formactionjavascriptcatalogguard.js —— 表单 action 注入目录。
//
// 威胁模型：
//   form action/formaction=javascript: 或方法覆盖头注入可在提交时执行脚本/改投端点，
//   action 应固定。纯字符查表，不用正则。

const FAS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const FAS_BLOCK = Object.freeze([
  'javascript:',
  'formaction-javascript',
  'x-http-method-override',
  'action-input',
])

const FAS_WARN = Object.freeze([
  'action-http',
])

const FAS_ALLOW = Object.freeze([
  'https-fixed-action',
])

function FASLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FASIn (list, v) {
  for (const x of list) { if (FASLower(x) === v) return true }
  return false
}

function FASClassify (tok) {
  const v = FASLower(String(tok == null ? '' : tok).trim())
  if (FASIn(FAS_BLOCK, v)) return FAS_CLASS.BLOCK
  if (FASIn(FAS_WARN, v)) return FAS_CLASS.WARN
  if (FASIn(FAS_ALLOW, v)) return FAS_CLASS.ALLOW
  return FAS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  FAS_CLASS: FAS_CLASS,
  FAS_BLOCK: FAS_BLOCK,
  FAS_WARN: FAS_WARN,
  FAS_ALLOW: FAS_ALLOW,
  FASClassify: FASClassify
})
