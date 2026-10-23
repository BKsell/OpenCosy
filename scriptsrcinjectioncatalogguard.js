'use strict'

// scriptsrcinjectioncatalogguard.js —— 脚本注入 Sink 目录。
//
// 威胁模型：
//   createElement('script') 后赋外部 src、appendChild、动态 import() 不可信源可加载任意脚本，
//   应有 nonce 与固定源。纯字符查表，不用正则。

const SRS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const SRS_BLOCK = Object.freeze([
  'createelement-script',
  'appendchild-script',
  'import()-untrusted',
  'importmap-untrusted',
])

const SRS_WARN = Object.freeze([
  'text/javascript-dynamic',
])

const SRS_ALLOW = Object.freeze([
  'nonce-script',
  'same-origin',
])

function SRSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SRSIn (list, v) {
  for (const x of list) { if (SRSLower(x) === v) return true }
  return false
}

function SRSClassify (tok) {
  const v = SRSLower(String(tok == null ? '' : tok).trim())
  if (SRSIn(SRS_BLOCK, v)) return SRS_CLASS.BLOCK
  if (SRSIn(SRS_WARN, v)) return SRS_CLASS.WARN
  if (SRSIn(SRS_ALLOW, v)) return SRS_CLASS.ALLOW
  return SRS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  SRS_CLASS: SRS_CLASS,
  SRS_BLOCK: SRS_BLOCK,
  SRS_WARN: SRS_WARN,
  SRS_ALLOW: SRS_ALLOW,
  SRSClassify: SRSClassify
})
