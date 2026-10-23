'use strict'

// storagekeycatalogguard.js —— Web Storage/IndexedDB 敏感键名目录。
//
// 威胁模型：
//   localStorage/sessionStorage/IDB 是持久明文存储，令牌/密码/PII 不应写入。本模块按键名目录与片段判定，
//   纯字符，不用正则。

const SKC_REASON = Object.freeze({
  BLOCK: 'storagekeycatalog-input-hits-blocked-catalog',
  WARN: 'storagekeycatalog-input-hits-review-catalog',
  PREFIX: 'storagekeycatalog-input-hits-dangerous-prefix',
  EMPTY: 'storagekeycatalog-input-is-empty'
})

const SKC_BLOCK = Object.freeze([
  'password',
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'client_secret',
  'private_key',
  'session_token',
  'jwt',
  'authorization',
  'credit_card',
  'cvv',
  'ssn',
  'api_key',
])

const SKC_WARN = Object.freeze([
  'email',
  'phone',
  'user_id',
  'uuid',
  'device_id',
  'session_id',
  'ip',
  'address',
  'lat',
  'lng',
])

const SKC_ALLOW = Object.freeze([
  'theme',
  'lang',
  'volume',
  'sidebar_collapsed',
  'last_tab',
  'drafts_count',
  'preferences',
])

const SKC_PREFIX_LIT = Object.freeze([
])
const SKC_PREFIX_REASON = Object.freeze([
])

function SKCLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function SKCIn (list, v) {
  for (const x of list) { if (SKCLower(x) === v) return true }
  return false
}

function SKCSplit (inStr) {
  const out = []
  let start = -1
  for (let i = 0; i <= inStr.length; i++) {
    const end = i === inStr.length
  let sep = false
    if (!end) { const c = inStr[i]; sep = c === ' ' || c === '\t' || c === '\n' || c === '\r' }
    if (end || sep) { if (start >= 0) { out.push(inStr.slice(start, i)); start = -1 } }
    else if (start < 0) { start = i } }
  return out
}

class SKCGuard {
  static get blockList () { return SKC_BLOCK }
  static get warnList () { return SKC_WARN }
  static get allowList () { return SKC_ALLOW }
  static get prefixLit () { return SKC_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: SKC_REASON.EMPTY }] }
    for (const tok of SKCSplit(inStr)) {
      const cmp = SKCLower(String(tok).trim())
      if (SKCIn(SKC_BLOCK, cmp)) findings.push({ reason: SKC_REASON.BLOCK, detail: cmp })
      else if (SKCIn(SKC_WARN, cmp)) findings.push({ reason: SKC_REASON.WARN, detail: cmp })
      for (let i = 0; i < SKC_PREFIX_LIT.length; i++) {
        const lit = SKC_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: SKC_REASON.PREFIX, detail: SKC_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  SKC_REASON: SKC_REASON,
  SKC_BLOCK: SKC_BLOCK,
  SKC_WARN: SKC_WARN,
  SKC_ALLOW: SKC_ALLOW,
  SKCGuard: SKCGuard
})
