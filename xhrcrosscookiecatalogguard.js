'use strict'

// xhrcrosscookiecatalogguard.js —— XHR 跨域/同步风险目录。
//
// 威胁模型：
//   XHR 对跨源带凭据、手写 Cookie 头或同步 open 会泄露会话或阻塞 UI，
//   应异步同源。纯字符查表，不用正则。

const XHR_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const XHR_BLOCK = Object.freeze([
  'withcredentials-cross',
  'setrequestheader-cookie',
  'open-sync',
])

const XHR_WARN = Object.freeze([
  'xhr-redirect',
])

const XHR_ALLOW = Object.freeze([
  'async-same-origin',
])

function XHRLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function XHRIn (list, v) {
  for (const x of list) { if (XHRLower(x) === v) return true }
  return false
}

function XHRClassify (tok) {
  const v = XHRLower(String(tok == null ? '' : tok).trim())
  if (XHRIn(XHR_BLOCK, v)) return XHR_CLASS.BLOCK
  if (XHRIn(XHR_WARN, v)) return XHR_CLASS.WARN
  if (XHRIn(XHR_ALLOW, v)) return XHR_CLASS.ALLOW
  return XHR_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  XHR_CLASS: XHR_CLASS,
  XHR_BLOCK: XHR_BLOCK,
  XHR_WARN: XHR_WARN,
  XHR_ALLOW: XHR_ALLOW,
  XHRClassify: XHRClassify
})
