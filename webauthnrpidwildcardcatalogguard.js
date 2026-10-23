'use strict'

// webauthnrpidwildcardcatalogguard.js —— WebAuthn RP/校验配置目录。
//
// 威胁模型：
//   rpId 用过宽可注册域、userVerification=none 不验证用户、direct 证明过度收集设备，
//   rpId 应为精确站点。纯字符查表，不用正则。

const WAC_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WAC_BLOCK = Object.freeze([
  'rpid-wildcard',
  'userverification-none',
  'attestation-direct',
  'rp-exact-mismatch',
])

const WAC_WARN = Object.freeze([
  'uv=discouraged',
])

const WAC_ALLOW = Object.freeze([
  'rp-exact',
  'userverification-required',
])

function WACLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WACIn (list, v) {
  for (const x of list) { if (WACLower(x) === v) return true }
  return false
}

function WACClassify (tok) {
  const v = WACLower(String(tok == null ? '' : tok).trim())
  if (WACIn(WAC_BLOCK, v)) return WAC_CLASS.BLOCK
  if (WACIn(WAC_WARN, v)) return WAC_CLASS.WARN
  if (WACIn(WAC_ALLOW, v)) return WAC_CLASS.ALLOW
  return WAC_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WAC_CLASS: WAC_CLASS,
  WAC_BLOCK: WAC_BLOCK,
  WAC_WARN: WAC_WARN,
  WAC_ALLOW: WAC_ALLOW,
  WACClassify: WACClassify
})
