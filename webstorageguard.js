'use strict'

// webstorageguard.js —— localStorage/sessionStorage/IndexedDB 存放敏感数据守卫。
//
// 威胁模型：
//   页面把 token、记住我凭据、PII 存进 localStorage：永久驻留磁盘、同源任意脚本（含被 XSS 注入的）
//   可读，且不受会话结束清理。sessionStorage 生命周期短一些但同样对同源脚本敞开。规则：
//     - localStorage 禁止存高敏数据（口令、可直接兑换的 token、银行卡）；
//     - 敏感字段必须有过期/会话语义，倾向内存或 sessionStorage；
//     - 写入前对键名做分类（token/password/secret/ssn/creditcard 等）；
//     - 退出时应清空持久存储中的会话数据。
//   纯字符键名匹配，不使用正则。

const WS2_REASON = Object.freeze({
  SENSITIVE_IN_LOCAL: 'sensitive-value-stored-in-persistent-localstorage',
  SENSITIVE_KEY_IN_LOCAL: 'sensitive-key-name-used-with-localstorage',
  PII_IN_STORAGE: 'personally-identifying-data-written-to-web-storage',
  NO_EXPIRY: 'persisted-session-token-has-no-expiry-policy'
})

const SECRET_KEY_TOKENS = [
  'password', 'passwd', 'pwd', 'secret', 'token', 'access_token', 'refresh_token',
  'apikey', 'api_key', 'client_secret', 'private_key', 'credential', 'auth'
]
const PII_KEY_TOKENS = [
  'ssn', 'idcard', 'creditcard', 'credit_card', 'cardnumber', 'card_number',
  'passport', 'bankcard'
]

function wsLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function wsHasToken (lowerKey, tokens) {
  for (const t of tokens) {
    if (lowerKey.indexOf(t) >= 0) return t
  }
  return null
}

class WebStorageGuard {
  // area: 'local' | 'session' | 'memory'；entry: { key, value, classifiedAs, hasExpiryPolicy }
  evaluate (entry) {
    const e = entry || {}
    const area = String(e.area || 'local')
    const key = wsLower(String(e.key || ''))
    const findings = []

    const secretTok = wsHasToken(key, SECRET_KEY_TOKENS)
    const piiTok = wsHasToken(key, PII_KEY_TOKENS)
    const classifiedSecret = e.classifiedAs === 'secret' || e.classifiedAs === 'credential'

    if (piiTok || e.classifiedAs === 'pii') findings.push({ reason: WS2_REASON.PII_IN_STORAGE, detail: piiTok || 'classified' })

    if (area === 'local') {
      if (secretTok || classifiedSecret) {
        findings.push({ reason: WS2_REASON.SENSITIVE_KEY_IN_LOCAL, detail: secretTok || 'classified' })
      }
      if (e.valueIsSecret === true || classifiedSecret) {
        findings.push({ reason: WS2_REASON.SENSITIVE_IN_LOCAL })
      }
      if ((secretTok === 'token' || secretTok === 'access_token' || secretTok === 'refresh_token') &&
          e.hasExpiryPolicy !== true) {
        findings.push({ reason: WS2_REASON.NO_EXPIRY })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 退出登录审计：持久区里不得残留会话密钥。
  auditLogout (remainingKeys) {
    const findings = []
    for (const k of remainingKeys || []) {
      const low = wsLower(String(k))
      if (wsHasToken(low, ['token', 'secret', 'credential', 'password'])) {
        findings.push({ reason: WS2_REASON.SENSITIVE_KEY_IN_LOCAL, detail: low })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  WS2_REASON: WS2_REASON,
  SECRET_KEY_TOKENS: SECRET_KEY_TOKENS,
  WebStorageGuard: WebStorageGuard
})
