'use strict'

// certpinverifyguard.js —— 证书公钥钉扎（SPKI pin）校验与轮换守卫。
//
// 威胁模型：
//   浏览器对自有服务做证书钉扎以防被受感染的 CA 中间人。错误实现：
//     - 只钉一个 pin，证书轮换后整站不可用（导致被迫关闭校验）；
//     - 比较 pin 时用普通字符串相等（时序侧信道，虽弱但不该留）；
//     - 服务端链里没有任何一个 pin 命中就放行（校验形同虚设）；
//     - 接受空 pin 集合；命中了已吊销 pin。
//   本模块管理 pin 集合（当前 pin + 备份 pin + 已吊销 pin），并在"链中 SPKI 哈希集合"与配置间
//   做匹配。哈希比较使用固定工作量比较。纯字符判定，不使用正则。

const SPNP_REASON = Object.freeze({
  EMPTY_PIN_SET: 'pin-set-has-no-trusted-pins',
  NO_BACKUP_PIN: 'pin-set-has-no-backup-pin-for-rotation',
  NO_MATCH: 'server-chain-matches-no-pinned-spki',
  REVOKED_PIN_MATCHED: 'server-chain-matches-revoked-pin',
  MALFORMED_PIN: 'pin-value-not-valid-base64-spki',
  EMPTY_CHAIN: 'server-presented-empty-certificate-chain'
})

const PIN_LEN = 44 // sha256 base64（含一个 '='）

function spnpTimingEqual (a, b) {
  const max = a.length >= b.length ? a.length : b.length
  let diff = a.length ^ b.length
  for (let i = 0; i < max; i++) {
    const ca = i < a.length ? a.charCodeAt(i) : 0
    const cb = i < b.length ? b.charCodeAt(i) : 0
    diff |= ca ^ cb
  }
  return diff === 0
}

function spnpValidPin (pin) {
  if (typeof pin !== 'string' || pin.length !== PIN_LEN) return false
  const ok = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
  for (let i = 0; i < pin.length; i++) if (ok.indexOf(pin[i]) < 0) return false
  return pin[PIN_LEN - 1] === '='
}

class CertPinVerifyGuard {
  // config: { pins:[当前+备份 base64], revoked:[...] }
  constructor (config) {
    const c = config || {}
    this.pins = c.pins || []
    this.revoked = c.revoked || []
  }

  auditConfig () {
    const findings = []
    if (this.pins.length === 0) findings.push({ reason: SPNP_REASON.EMPTY_PIN_SET })
    for (const p of this.pins.concat(this.revoked)) {
      if (!spnpValidPin(p)) findings.push({ reason: SPNP_REASON.MALFORMED_PIN, detail: String(p).slice(0, 8) })
    }
    if (this.pins.length < 2) findings.push({ reason: SPNP_REASON.NO_BACKUP_PIN })
    return { safe: findings.length === 0, findings: findings }
  }

  // chainHashes: 服务器链上每张证书的 SPKI base64 数组。
  verify (chainHashes) {
    const findings = []
    const cfg = this.auditConfig()
    findings.push.apply(findings, cfg.findings)
    if (!Array.isArray(chainHashes) || chainHashes.length === 0) {
      findings.push({ reason: SPNP_REASON.EMPTY_CHAIN })
      return { safe: false, findings: findings, matched: null }
    }
    let matched = null
    for (const presented of chainHashes) {
      for (const revoked of this.revoked) {
        if (spnpTimingEqual(presented, revoked)) {
          findings.push({ reason: SPNP_REASON.REVOKED_PIN_MATCHED })
        }
      }
      for (const trusted of this.pins) {
        if (matched === null && spnpTimingEqual(presented, trusted)) matched = trusted
      }
    }
    if (matched === null) findings.push({ reason: SPNP_REASON.NO_MATCH })
    // 命中吊销 pin 时即使也命中当前 pin 也判失败
    const revokedHit = findings.some((f) => f.reason === SPNP_REASON.REVOKED_PIN_MATCHED)
    return { safe: matched !== null && !revokedHit && cfg.safe, findings: findings, matched: matched }
  }
}

module.exports = Object.freeze({
  SPNP_REASON: SPNP_REASON,
  spnpValidPin: spnpValidPin,
  CertPinVerifyGuard: CertPinVerifyGuard
})
