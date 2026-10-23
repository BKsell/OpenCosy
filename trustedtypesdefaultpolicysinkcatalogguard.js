'use strict'

// trustedtypesdefaultpolicysinkcatalogguard.js —— Trusted Types 策略目录。
//
// 威胁模型：
//   默认策略用未净化输入 createHTML 或仅 report-only 不能阻止 DOM XSS，
//   应 enforce 且策略内集中净化。纯字符查表，不用正则。

const TTS_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const TTS_BLOCK = Object.freeze([
  'default-policy-none',
  'createhtml-unsanitized',
  'report-only',
  'createScript-raw',
])

const TTS_WARN = Object.freeze([
  'createScriptURL-unchecked',
])

const TTS_ALLOW = Object.freeze([
  'enforced-sanitized',
])

function TTSLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function TTSIn (list, v) {
  for (const x of list) { if (TTSLower(x) === v) return true }
  return false
}

function TTSClassify (tok) {
  const v = TTSLower(String(tok == null ? '' : tok).trim())
  if (TTSIn(TTS_BLOCK, v)) return TTS_CLASS.BLOCK
  if (TTSIn(TTS_WARN, v)) return TTS_CLASS.WARN
  if (TTSIn(TTS_ALLOW, v)) return TTS_CLASS.ALLOW
  return TTS_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  TTS_CLASS: TTS_CLASS,
  TTS_BLOCK: TTS_BLOCK,
  TTS_WARN: TTS_WARN,
  TTS_ALLOW: TTS_ALLOW,
  TTSClassify: TTSClassify
})
