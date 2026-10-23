'use strict'

// consolesensitivelogcatalogguard.js —— 控制台敏感输出目录。
//
// 威胁模型：
//   console.log/warn 打印 password/token/PII，生产构建若保留会被调试采集或截图泄露，
//   应统一脱敏 logger。纯字符查表，不用正则。

const CSL_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CSL_BLOCK = Object.freeze([
  'console.log-password',
  'console-token',
  'console.pii',
  'console.error-stack-secret',
])

const CSL_WARN = Object.freeze([
  'console.warn-data',
])

const CSL_ALLOW = Object.freeze([
  'redacted-logger',
])

function CSLLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CSLIn (list, v) {
  for (const x of list) { if (CSLLower(x) === v) return true }
  return false
}

function CSLClassify (tok) {
  const v = CSLLower(String(tok == null ? '' : tok).trim())
  if (CSLIn(CSL_BLOCK, v)) return CSL_CLASS.BLOCK
  if (CSLIn(CSL_WARN, v)) return CSL_CLASS.WARN
  if (CSLIn(CSL_ALLOW, v)) return CSL_CLASS.ALLOW
  return CSL_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CSL_CLASS: CSL_CLASS,
  CSL_BLOCK: CSL_BLOCK,
  CSL_WARN: CSL_WARN,
  CSL_ALLOW: CSL_ALLOW,
  CSLClassify: CSLClassify
})
