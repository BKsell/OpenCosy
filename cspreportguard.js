'use strict'

// cspreportguard.js —— Content-Security-Policy-Report-Only / report-uri 上报端点守卫。
//
// 威胁模型：
//   CSP 违规报告含有被拦截资源的完整 URL、文档 URI、有时含片段/查询里的敏感参数。上报端点配置
//   不当会造成：
//     - report-uri/report-to 指向第三方或 http（违规数据外泄/被篡改）；
//     - 只部署 Report-Only 却以为在强制执行（违规只记录不阻断）；
//     - report-uri 已废弃但单独使用、且没有 report-to（现代浏览器行为不一）；
//     - 上报样本未做采样，含大量用户 URL（隐私/放大）。
//   本模块审计 CSP 头里的报告配置与执行模式。纯字符解析，不使用正则。

const CR_REASON = Object.freeze({
  REPORT_URI_HTTP: 'csp-report-uri-is-not-https',
  REPORT_URI_FOREIGN: 'csp-report-uri-points-to-foreign-host',
  REPORT_ONLY_ASSUMED_ENFORCING: 'content-security-policy-report-only-does-not-block',
  REPORT_URI_DEPRECATED_ONLY: 'deprecated-report-uri-used-without-report-to',
  REPORTING_MISSING: 'csp-has-no-reporting-endpoint-at-all'
})

function crLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function crIsSpace (c) {
  return c === ' ' || c === '\t' || c === ',' || c === ';'
}

// 从 CSP 头值里取某指令的参数串。
function crDirective (cspLower, name) {
  const s = cspLower
  let from = 0
  while (true) {
    const idx = s.indexOf(name, from)
    if (idx < 0) return null
    const before = idx === 0 ? ' ' : s[idx - 1]
    const afterPos = idx + name.length
    const after = afterPos < s.length ? s[afterPos] : ' '
    if (crIsSpace(before) && crIsSpace(after)) {
      let rest = s.slice(afterPos)
      const semi = rest.indexOf(';')
      if (semi >= 0) rest = rest.slice(0, semi)
      return rest.trim()
    }
    from = idx + 1
  }
}

function crFirstToken (s) {
  let i = 0
  while (i < s.length && (s[i] === ' ' || s[i] === '\t')) i++
  const start = i
  while (i < s.length && s[i] !== ' ' && s[i] !== '\t') i++
  return s.slice(start, i)
}

function crHost (url) {
  const sep = String(url).indexOf('://')
  if (sep < 0) return { scheme: '', host: '' }
  let rest = String(url).slice(sep + 3)
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '/' || rest[i] === '?') { rest = rest.slice(0, i); break }
  }
  return { scheme: crLower(String(url).slice(0, sep)), host: crLower(rest) }
}

class CspReportGuard {
  // in: { headerKind:'enforce'|'report-only', csp, policyHost }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const csp = crLower(String(inp.csp || ''))
    const kind = crLower(String(inp.headerKind || 'enforce'))
    const policyHost = crLower(String(inp.policyHost || ''))

    const reportUri = crDirective(csp, 'report-uri')
    const reportTo = crDirective(csp, 'report-to')
    const hasEndpoint = (reportUri && reportUri.length > 0) || (reportTo && reportTo.length > 0)
    if (!hasEndpoint) findings.push({ reason: CR_REASON.REPORTING_MISSING })

    if (reportUri && reportUri.length > 0) {
      if (!reportTo) findings.push({ reason: CR_REASON.REPORT_URI_DEPRECATED_ONLY })
      const first = crFirstToken(reportUri)
      const sh = crHost(first)
      if (sh.scheme === 'http') findings.push({ reason: CR_REASON.REPORT_URI_HTTP })
      if (policyHost && sh.host && sh.host !== policyHost) {
        findings.push({ reason: CR_REASON.REPORT_URI_FOREIGN, detail: sh.host })
      }
    }
    if (kind === 'report-only') findings.push({ reason: CR_REASON.REPORT_ONLY_ASSUMED_ENFORCING })
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  CR_REASON: CR_REASON,
  crDirective: crDirective,
  CspReportGuard: CspReportGuard
})
