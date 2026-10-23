'use strict'

// xssprotectionguard.js —— X-XSS-Protection 遗留头守卫。
//
// 威胁模型：
//   X-XSS-Protection 是老版 IE/Chrome 的"反射型 XSS 审计器"。现代规范已废弃它，因为审计器本身
//   引入过新的 XSS 旁路（可被精心构造的响应利用），且与 CSP 重复。现代安全建议是显式关闭：
//     X-XSS-Protection: 0
//   危险/无效配置：
//     - 1; mode=block：启用审计器（旧行为，现代浏览器可能忽略或引入旁路）；
//     - 1; report=...：启用且上报，同样不推荐；
//     - 缺失：现代浏览器默认已关闭，但显式置 0 可确保旧引擎行为一致（本模块默认只提示）。
//
// 本模块判定唯一推荐值是否为 "0"。

const XXP_HEADER = 'x-xss-protection'

const XXP_REASON = Object.freeze({
  ENABLED_BLOCK: 'xxp-enabled-mode-block',
  ENABLED_REPORT: 'xxp-enabled-report',
  ENABLED_PLAIN: 'xxp-enabled',
  NOT_EXPLICIT_ZERO: 'xxp-not-explicit-zero',
  INVALID: 'xxp-invalid-value',
  MULTIPLE: 'xxp-multiple-values',
  CONTROL_CHAR: 'xxp-control-char'
})

function defaultXxpPolicy () {
  return { requireZero: false, rejectControlChars: true }
}

function xxpHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class XssProtectionGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultXxpPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const findings = []
    let state = 'absent'
    if (headerValue === null || headerValue === undefined) {
      // 缺失默认不算违规（现代浏览器默认关闭）；requireZero 时提示应显式置 0。
      if (this.policy.requireZero) {
        return { safe: false, state: state, explicitZero: false, findings: [{ reason: XXP_REASON.NOT_EXPLICIT_ZERO }] }
      }
      return { safe: true, state: state, explicitZero: false, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim()
    if (this.policy.rejectControlChars && xxpHasControlChar(raw)) {
      findings.push({ reason: XXP_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: XXP_REASON.MULTIPLE })
    }
    const head = value.split(';')[0].split(',')[0].trim()
    const lower = value.toLowerCase()
    if (head === '0') {
      state = 'disabled'
      return { safe: findings.length === 0, state: state, explicitZero: true, findings }
    }
    if (head === '1') {
      state = 'enabled'
      if (lower.indexOf('mode=block') >= 0) {
        findings.push({ reason: XXP_REASON.ENABLED_BLOCK })
      } else if (lower.indexOf('report=') >= 0) {
        findings.push({ reason: XXP_REASON.ENABLED_REPORT })
      } else {
        findings.push({ reason: XXP_REASON.ENABLED_PLAIN })
      }
      return { safe: false, state: state, explicitZero: false, findings }
    }
    findings.push({ reason: XXP_REASON.INVALID, value: head })
    return { safe: false, state: 'invalid', explicitZero: false, findings }
  }
}

module.exports = Object.freeze({
  XXP_HEADER: XXP_HEADER,
  XXP_REASON: XXP_REASON,
  defaultXxpPolicy: defaultXxpPolicy,
  XssProtectionGuard: XssProtectionGuard
})
