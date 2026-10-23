'use strict'

// oauthstateguard.js —— OAuth/OIDC 授权码流程的 state CSRF 守卫。
//
// 威胁模型：
//   浏览器发起第三方登录跳转 /auth?state=...，回调时若不校验 state，攻击者可用自己的授权码替换，
//   绑定受害者账号（登录 CSRF）；state 可预测、过短、跨流程复用、回调后未一次性消费都会失效。
//   本模块管理 state 的生成、登记、一次性校验与到期：
//     - 登记 state 绑定的发起上下文（returnTo、随机 nonce）；
//     - consume 必须精确匹配、存在且未过期、且只能消费一次；
//     - 不允许空 state、重复登记同一 state（碰撞/重放）。
//   随机来源交给注入的 rng（便于测试与替换为 crypto），不使用正则。

const OS_REASON = Object.freeze({
  STATE_EMPTY: 'oauth-state-empty',
  STATE_TOO_SHORT: 'oauth-state-too-short',
  STATE_ALREADY_ISSUED: 'oauth-state-collision-already-issued',
  STATE_UNKNOWN: 'oauth-state-not-recognized-on-callback',
  STATE_EXPIRED: 'oauth-state-expired',
  STATE_REUSED: 'oauth-state-replayed-after-consumption',
  CONTEXT_MISMATCH: 'oauth-callback-context-mismatch'
})

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

function defaultRng (nbytes) {
  const out = new Array(nbytes)
  for (let i = 0; i < nbytes; i++) out[i] = Math.floor(Math.random() * 256)
  return out
}

function osEncode (bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += ALPHABET[bytes[i] & 63]
  return s
}

class OAuthStateGuard {
  // opts: { ttlMs, stateBytes, now, rng }
  constructor (opts) {
    const o = opts || {}
    this.ttlMs = typeof o.ttlMs === 'number' ? o.ttlMs : 10 * 60 * 1000
    this.stateBytes = typeof o.stateBytes === 'number' ? o.stateBytes : 32
    this.clock = typeof o.now === 'function' ? o.now : function () { return Date.now() }
    this.rng = typeof o.rng === 'function' ? o.rng : defaultRng
    this.issued = new Map()
  }

  issue (context) {
    const state = osEncode(this.rng(this.stateBytes))
    if (state.length < 16) {
      return { safe: false, state: state, findings: [{ reason: OS_REASON.STATE_TOO_SHORT }] }
    }
    if (this.issued.has(state)) {
      return { safe: false, state: state, findings: [{ reason: OS_REASON.STATE_ALREADY_ISSUED }] }
    }
    this.issued.set(state, { context: context || null, expires: this.clock() + this.ttlMs, used: false })
    return { safe: true, state: state, findings: [] }
  }

  consume (state, expectedContext) {
    if (!state) return { safe: false, findings: [{ reason: OS_REASON.STATE_EMPTY }] }
    const rec = this.issued.get(state)
    if (!rec) return { safe: false, findings: [{ reason: OS_REASON.STATE_UNKNOWN }] }
    if (rec.used) return { safe: false, findings: [{ reason: OS_REASON.STATE_REUSED }] }
    if (this.clock() > rec.expires) {
      this.issued.delete(state)
      return { safe: false, findings: [{ reason: OS_REASON.STATE_EXPIRED }] }
    }
    if (expectedContext !== undefined && !osDeepEqual(expectedContext, rec.context)) {
      return { safe: false, findings: [{ reason: OS_REASON.CONTEXT_MISMATCH }] }
    }
    // 保留 used 墓碑：再次提交同一 state 判定为重放，而非"未知"。
    rec.used = true
    return { safe: true, context: rec.context, findings: [] }
  }
}

// 仅支持 JSON 形态（对象/数组/原始值）的结构化相等比较。
function osDeepEqual (a, b) {
  if (a === b) return true
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false
  const ka = Object.keys(a)
  const kb = Object.keys(b)
  if (ka.length !== kb.length) return false
  for (const k of ka) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false
    if (!osDeepEqual(a[k], b[k])) return false
  }
  return true
}

module.exports = Object.freeze({
  OS_REASON: OS_REASON,
  OAuthStateGuard: OAuthStateGuard
})
