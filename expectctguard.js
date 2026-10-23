'use strict'

// expectctguard.js —— Expect-CT 响应头守卫。
//
// 威胁模型：
//   Expect-CT 曾用于强制浏览器校验证书透明度（CT）。该头已被 Chrome 移除/废弃，但错误配置仍会
//   在仍支持的客户端上造成意外：report-uri 指向第三方会把证书信息外发；max-age=0 表示撤销；
//   拼写错误导致整条被忽略。本模块按纵深防御解析，确保若设置就必须有合理 max-age，且
//   report-uri 必须是 https。
//
// 建议：新站点不必设置；本守卫用于发现"设了但设错"的情况。

const ECT_HEADER = 'expect-ct'

const ECT_REASON = Object.freeze({
  EMPTY: 'ect-empty',
  MAX_AGE_MISSING: 'ect-max-age-missing',
  MAX_AGE_ZERO: 'ect-max-age-zero',
  BAD_MAX_AGE: 'ect-bad-max-age',
  DUPLICATE_MAX_AGE: 'ect-duplicate-max-age',
  INSECURE_REPORT_URI: 'ect-insecure-report-uri',
  UNKNOWN_DIRECTIVE: 'ect-unknown-directive',
  CONTROL_CHAR: 'ect-control-char'
})

function defaultExpectCtPolicy () {
  return { rejectControlChars: true, rejectUnknownDirective: false }
}

function ectHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

function ectIsDigits (s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return true
}

class ExpectCtGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultExpectCtPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      // 不设置是允许的（头已废弃）。
      return { safe: true, present: false, findings }
    }
    const raw = String(headerValue)
    if (raw.trim() === '') {
      findings.push({ reason: ECT_REASON.EMPTY })
      return { safe: false, present: true, findings }
    }
    if (this.policy.rejectControlChars && ectHasControlChar(raw)) {
      findings.push({ reason: ECT_REASON.CONTROL_CHAR })
    }
    let maxAge = null
    let maxAgeCount = 0
    let reportUri = null
    let enforce = false
    const parts = raw.split(',')
    for (let i = 0; i < parts.length; i++) {
      const tok = parts[i].trim()
      if (tok === '') continue
      const eq = tok.indexOf('=')
      let name = tok.toLowerCase()
      let val = null
      if (eq >= 0) {
        name = tok.slice(0, eq).trim().toLowerCase()
        val = tok.slice(eq + 1).trim()
        // 纯字符去掉成对包裹的双引号（不使用正则）。
        if (val.length >= 2 && val.charAt(0) === '"' && val.charAt(val.length - 1) === '"') {
          val = val.slice(1, val.length - 1)
        }
      }
      if (name === 'max-age') {
        maxAgeCount++
        if (val !== null && ectIsDigits(val)) maxAge = parseInt(val, 10)
        else findings.push({ reason: ECT_REASON.BAD_MAX_AGE })
      } else if (name === 'report-uri') {
        reportUri = val
      } else if (name === 'enforce') {
        enforce = true
      } else if (this.policy.rejectUnknownDirective) {
        findings.push({ reason: ECT_REASON.UNKNOWN_DIRECTIVE, directive: name })
      }
    }
    if (maxAgeCount >= 2) findings.push({ reason: ECT_REASON.DUPLICATE_MAX_AGE })
    if (maxAgeCount === 0) findings.push({ reason: ECT_REASON.MAX_AGE_MISSING })
    else if (maxAge === 0) findings.push({ reason: ECT_REASON.MAX_AGE_ZERO })
    if (reportUri !== null && reportUri.toLowerCase().indexOf('https://') !== 0) {
      findings.push({ reason: ECT_REASON.INSECURE_REPORT_URI })
    }
    return { safe: findings.length === 0, present: true, maxAge: maxAge, enforce: enforce, reportUri: reportUri, findings: findings }
  }
}

module.exports = Object.freeze({
  ECT_HEADER: ECT_HEADER,
  ECT_REASON: ECT_REASON,
  defaultExpectCtPolicy: defaultExpectCtPolicy,
  ExpectCtGuard: ExpectCtGuard
})
