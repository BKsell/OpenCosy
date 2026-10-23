'use strict'

// paymentrequestthirdpartycatalogguard.js —— Payment Request 风险目录。
//
// 威胁模型：
//   PaymentRequest 接受第三方 merchant 或已废弃 basic-card，method 用 http URL 可被劫持，
//   应 https 白名单支付方式。纯字符查表，不用正则。

const PAY_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const PAY_BLOCK = Object.freeze([
  'basic-card',
  'third-party-merchant',
  'method-http',
  'paymentrequest-input',
])

const PAY_WARN = Object.freeze([
  'method-url',
])

const PAY_ALLOW = Object.freeze([
  'https-allowlist',
])

function PAYLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function PAYIn (list, v) {
  for (const x of list) { if (PAYLower(x) === v) return true }
  return false
}

function PAYClassify (tok) {
  const v = PAYLower(String(tok == null ? '' : tok).trim())
  if (PAYIn(PAY_BLOCK, v)) return PAY_CLASS.BLOCK
  if (PAYIn(PAY_WARN, v)) return PAY_CLASS.WARN
  if (PAYIn(PAY_ALLOW, v)) return PAY_CLASS.ALLOW
  return PAY_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  PAY_CLASS: PAY_CLASS,
  PAY_BLOCK: PAY_BLOCK,
  PAY_WARN: PAY_WARN,
  PAY_ALLOW: PAY_ALLOW,
  PAYClassify: PAYClassify
})
