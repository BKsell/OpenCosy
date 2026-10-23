'use strict'

// coopguard.js —— Cross-Origin-Opener-Policy（跨源打开者隔离）守卫。
//
// 威胁模型：
//   没有 COOP 时，跨源弹出窗口与打开者共享同一 browsing context group，可通过 window.opener
//   相互引用（跨源读有限，但可做导航、计时侧信道、Spectre 类跨源数据推断、反向 tabnabbing）。
//   COOP 隔离进程/上下文组：
//     - unsafe-none（默认）：完全不隔离；
//     - same-origin-allow-popups：与第三方弹窗保留引用（隔离打折）；
//     - same-origin：强隔离。
//   含密钥/账户的页面应 same-origin。本模块审计 COOP 值与页面敏感度是否匹配。纯字符判定。

const COOP_REASON = Object.freeze({
  MISSING: 'cross-origin-opener-policy-header-missing',
  UNSAFE_NONE: 'coop-is-unsafe-none-on-sensitive-page',
  ALLOW_POPUPS_ON_SENSITIVE: 'coop-same-origin-allow-popups-on-sensitive-page',
  UNKNOWN_VALUE: 'coop-value-unrecognized'
})

const KNOWN = ['unsafe-none', 'same-origin-allow-popups', 'same-origin']

function coopLower (s) {
  return String(s).trim().toLowerCase()
}

class CoopGuard {
  // in: { header:值或null, sensitive:bool }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    if (inp.header === undefined || inp.header === null || String(inp.header).trim() === '') {
      findings.push({ reason: COOP_REASON.MISSING })
      return { safe: false, findings: findings }
    }
    const v = coopLower(inp.header)
    if (KNOWN.indexOf(v) < 0) findings.push({ reason: COOP_REASON.UNKNOWN_VALUE, detail: v })
    if (inp.sensitive === true) {
      if (v === 'unsafe-none') findings.push({ reason: COOP_REASON.UNSAFE_NONE })
      if (v === 'same-origin-allow-popups') findings.push({ reason: COOP_REASON.ALLOW_POPUPS_ON_SENSITIVE })
    }
    return { safe: findings.length === 0, findings: findings, value: v }
  }
}

module.exports = Object.freeze({
  COOP_REASON: COOP_REASON,
  KNOWN: KNOWN,
  CoopGuard: CoopGuard
})
