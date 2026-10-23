'use strict'

// fetchcrosscredentialcatalogguard.js —— fetch 跨域凭据目录。
//
// 威胁模型：
//   fetch 对不可信 URL 用 credentials:include、mode:no-cors 且盲跟随重定向会带 Cookie 外发，
//   应同源并 manual 重定向。纯字符查表，不用正则。

const FES_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const FES_BLOCK = Object.freeze([
  'credentials-include-cross',
  'mode-no-cors',
  'redirect-follow-input',
  'fetch-input',
])

const FES_WARN = Object.freeze([
  'cors-cross',
])

const FES_ALLOW = Object.freeze([
  'same-origin',
  'redirect-manual',
])

function FESLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function FESIn (list, v) {
  for (const x of list) { if (FESLower(x) === v) return true }
  return false
}

function FESClassify (tok) {
  const v = FESLower(String(tok == null ? '' : tok).trim())
  if (FESIn(FES_BLOCK, v)) return FES_CLASS.BLOCK
  if (FESIn(FES_WARN, v)) return FES_CLASS.WARN
  if (FESIn(FES_ALLOW, v)) return FES_CLASS.ALLOW
  return FES_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  FES_CLASS: FES_CLASS,
  FES_BLOCK: FES_BLOCK,
  FES_WARN: FES_WARN,
  FES_ALLOW: FES_ALLOW,
  FESClassify: FESClassify
})
