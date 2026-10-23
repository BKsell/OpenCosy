'use strict'

// cooppolicyguard.js —— Cross-Origin-Opener-Policy（COOP）守卫。
//
// 威胁模型：
//   COOP 把顶层文档放进独立的浏览上下文组。缺失或 unsafe-none 时，新开的跨源窗口与本页共享
//   同一进程组、可经 window.opener 互相引用，带来弹窗篡改（tab-nabbing）、跨源计时 / Spectre
//   侧信道风险。值的收紧顺序：
//     unsafe-none（最宽，默认） < same-origin-allow-popups < same-origin（最严）。
//   另支持 noopener-allow-popups（较新，允许弹窗但断 opener）。
// 错配：非法值（头被忽略）、逗号多值、控制字符。

const COOP_HEADER = 'cross-origin-opener-policy'

const COOP_MODE = Object.freeze({
  UNSAFE_NONE: 'unsafe-none',
  SAME_ORIGIN_ALLOW_POPUPS: 'same-origin-allow-popups',
  SAME_ORIGIN: 'same-origin',
  NOOPENER_ALLOW_POPUPS: 'noopener-allow-popups'
})

const COOP_REASON = Object.freeze({
  MISSING: 'coop-missing',
  EMPTY: 'coop-empty',
  UNSAFE_NONE: 'coop-unsafe-none',
  WEAK_ISOLATION: 'coop-weak-isolation',
  INVALID: 'coop-invalid-value',
  MULTIPLE: 'coop-multiple-values',
  CONTROL_CHAR: 'coop-control-char'
})

// 隔离强度等级（越大越隔离）。
const COOP_LEVEL = Object.freeze({
  'unsafe-none': 0,
  'same-origin-allow-popups': 1,
  'noopener-allow-popups': 2,
  'same-origin': 3
})

function defaultCoopPolicy () {
  return { minLevel: 3, rejectControlChars: true }
}

function coopHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class CoopPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCoopPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: COOP_REASON.MISSING })
      return { safe: false, mode: null, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim().toLowerCase()
    if (value === '') {
      findings.push({ reason: COOP_REASON.EMPTY })
      return { safe: false, mode: null, findings }
    }
    if (pol.rejectControlChars && coopHasControlChar(raw)) {
      findings.push({ reason: COOP_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: COOP_REASON.MULTIPLE })
    }
    const single = value.split(',')[0].trim()
    const level = Object.prototype.hasOwnProperty.call(COOP_LEVEL, single) ? COOP_LEVEL[single] : -1
    if (level < 0) {
      findings.push({ reason: COOP_REASON.INVALID, value: single })
      return { safe: false, mode: null, findings }
    }
    if (single === COOP_MODE.UNSAFE_NONE) {
      findings.push({ reason: COOP_REASON.UNSAFE_NONE })
    } else if (level < pol.minLevel) {
      findings.push({ reason: COOP_REASON.WEAK_ISOLATION, mode: single })
    }
    return { safe: findings.length === 0, mode: single, level: level, findings }
  }
}

module.exports = Object.freeze({
  COOP_HEADER: COOP_HEADER,
  COOP_MODE: COOP_MODE,
  COOP_LEVEL: COOP_LEVEL,
  COOP_REASON: COOP_REASON,
  defaultCoopPolicy: defaultCoopPolicy,
  CoopPolicyGuard: CoopPolicyGuard
})
