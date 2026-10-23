'use strict'

// coepguard.js —— Cross-Origin-Embedder-Policy（COEP）守卫。
//
// 威胁模型：
//   COEP 要求文档加载的所有跨源子资源都显式授权（CORP 或 CORS），配合 COOP 可进入跨源隔离
//   状态，封锁 Spectre 类跨源读取。缺失或 unsafe-none 时，跨源资源默认可被无授权嵌入。
// 值收紧顺序：unsafe-none（最宽） < credentialless < require-corp（最严）。
// 常见错配：非法值（被忽略等于 unsafe-none）、逗号多值、只给 report-only 没给强制头。

const COEP_HEADER = 'cross-origin-embedder-policy'
const COEP_RO_HEADER = 'cross-origin-embedder-policy-report-only'

const COEP_MODE = Object.freeze({
  UNSAFE_NONE: 'unsafe-none',
  CREDENTIALLESS: 'credentialless',
  REQUIRE_CORP: 'require-corp'
})

const COEP_REASON = Object.freeze({
  MISSING: 'coep-missing',
  EMPTY: 'coep-empty',
  UNSAFE_NONE: 'coep-unsafe-none',
  WEAK: 'coep-not-require-corp',
  INVALID: 'coep-invalid-value',
  MULTIPLE: 'coep-multiple-values',
  REPORT_ONLY_WITHOUT_ENFORCE: 'coep-report-only-without-enforce',
  CONTROL_CHAR: 'coep-control-char'
})

const COEP_LEVEL = Object.freeze({
  'unsafe-none': 0,
  'credentialless': 1,
  'require-corp': 2
})

function defaultCoepPolicy () {
  return { minLevel: 2, rejectControlChars: true }
}

function coepHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class CrossOriginEmbedderPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCoepPolicy(), policy || {})
  }

  // headerValue：强制头值；reportOnly：可选的 report-only 头值（用于检测"只观察不强制"）。
  evaluate (headerValue, reportOnly) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: COEP_REASON.MISSING })
      if (reportOnly !== null && reportOnly !== undefined && String(reportOnly).trim() !== '') {
        findings.push({ reason: COEP_REASON.REPORT_ONLY_WITHOUT_ENFORCE })
      }
      return { safe: false, mode: null, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim().toLowerCase()
    if (value === '') {
      findings.push({ reason: COEP_REASON.EMPTY })
      return { safe: false, mode: null, findings }
    }
    if (pol.rejectControlChars && coepHasControlChar(raw)) {
      findings.push({ reason: COEP_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: COEP_REASON.MULTIPLE })
    }
    const single = value.split(';')[0].split(',')[0].trim()
    const level = Object.prototype.hasOwnProperty.call(COEP_LEVEL, single) ? COEP_LEVEL[single] : -1
    if (level < 0) {
      findings.push({ reason: COEP_REASON.INVALID, value: single })
      return { safe: false, mode: null, findings }
    }
    if (single === COEP_MODE.UNSAFE_NONE) {
      findings.push({ reason: COEP_REASON.UNSAFE_NONE })
    } else if (level < pol.minLevel) {
      findings.push({ reason: COEP_REASON.WEAK, mode: single })
    }
    return { safe: findings.length === 0, mode: single, level: level, findings }
  }
}

module.exports = Object.freeze({
  COEP_HEADER: COEP_HEADER,
  COEP_RO_HEADER: COEP_RO_HEADER,
  COEP_MODE: COEP_MODE,
  COEP_REASON: COEP_REASON,
  COEP_LEVEL: COEP_LEVEL,
  defaultCoepPolicy: defaultCoepPolicy,
  CrossOriginEmbedderPolicyGuard: CrossOriginEmbedderPolicyGuard
})
