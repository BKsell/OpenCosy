'use strict'

// metarefreshjavascriptcatalogguard.js —— meta refresh / equiv 风险目录。
//
// 威胁模型：
//   meta refresh 跳到 javascript: 或 http-equiv set-cookie/Content-Security-Policy 可由注入内容改安全策略，
//   不应允许用户控 meta。纯字符查表，不用正则。

const MRF_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const MRF_BLOCK = Object.freeze([
  'refresh-javascript',
  'http-equiv-set-cookie',
  'http-equiv-csp',
  'refresh-0-input',
])

const MRF_WARN = Object.freeze([
  'refresh-http',
])

const MRF_ALLOW = Object.freeze([
  'canonical',
  'refresh-https',
])

function MRFLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function MRFIn (list, v) {
  for (const x of list) { if (MRFLower(x) === v) return true }
  return false
}

function MRFClassify (tok) {
  const v = MRFLower(String(tok == null ? '' : tok).trim())
  if (MRFIn(MRF_BLOCK, v)) return MRF_CLASS.BLOCK
  if (MRFIn(MRF_WARN, v)) return MRF_CLASS.WARN
  if (MRFIn(MRF_ALLOW, v)) return MRF_CLASS.ALLOW
  return MRF_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  MRF_CLASS: MRF_CLASS,
  MRF_BLOCK: MRF_BLOCK,
  MRF_WARN: MRF_WARN,
  MRF_ALLOW: MRF_ALLOW,
  MRFClassify: MRFClassify
})
