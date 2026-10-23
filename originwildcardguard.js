'use strict'

// originwildcardguard.js —— 出站响应/接口的 Access-Control-Allow-Origin 通配策略守卫。
//
// 威胁模型：
//   浏览器内置页面要 fetch 启动器后端、本地帮助服务或扩展接口。错误的 CORS 响应：
//     - ACAO: * 且 Allow-Credentials: true（浏览器虽拒绝，但某些原生 fetch 实现会放行，等同泄露）；
//     - ACAO 直接反射任意 Origin（reflect-any），等于 *；
//     - 子域通配 https://*.evil.com、尾部后缀匹配（endsWith）把 notevil.com 也放行；
//     - 对 null origin（sandbox iframe、file:、data:）放行。
//   本模块审计 (allowedOrigin 配置值) 与 (请求 Origin, 响应 ACAO, credentials) 的组合。
//   纯字符处理，不使用正则。

const OW_REASON = Object.freeze({
  WILDCARD_WITH_CREDS: 'acao-wildcard-combined-with-allow-credentials',
  REFLECT_ANY: 'acao-reflects-arbitrary-origin',
  BAD_WILDCARD: 'allowed-origin-wildcard-pattern-too-broad',
  NULL_ORIGIN: 'null-origin-allowed',
  SCHEMELESS: 'allowed-origin-missing-scheme'
})

function owLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

// 审计一个"允许的 Origin 模式"。
function auditAllowedPattern (pattern) {
  const findings = []
  const p = String(pattern)
  const lower = owLower(p)
  if (lower === 'null') findings.push({ reason: OW_REASON.NULL_ORIGIN })
  if (lower === '*') return findings // 单纯 * 本身合法，危险在带 credentials
  if (lower.indexOf('://') < 0) findings.push({ reason: OW_REASON.SCHEMELESS })
  const star = p.indexOf('*')
  if (star >= 0) {
    const afterScheme = lower.indexOf('://') >= 0 ? lower.slice(lower.indexOf('://') + 3) : lower
    // *.example.com 之外，含多星号、星号在非标签首字符、裸顶级通配都过宽
    if (p.split('*').length - 1 > 1) findings.push({ reason: OW_REASON.BAD_WILDCARD })
    if (!afterScheme.startsWith('*.') || afterScheme === '*.') findings.push({ reason: OW_REASON.BAD_WILDCARD })
    const tldPart = afterScheme.slice(2)
    if (tldPart.indexOf('.') < 0) findings.push({ reason: OW_REASON.BAD_WILDCARD })
  }
  return findings
}

// 审计实际响应。allowCredentials 为布尔；acao 为响应头值；requestOrigin 为请求 Origin。
function auditResponse (opts) {
  const findings = []
  const acao = opts.acao === undefined || opts.acao === null ? '' : String(opts.acao)
  const lower = owLower(acao)
  if (opts.allowCredentials === true && lower === '*') {
    findings.push({ reason: OW_REASON.WILDCARD_WITH_CREDS })
  }
  if (lower === 'null') findings.push({ reason: OW_REASON.NULL_ORIGIN })
  if (opts.reflectAny === true && opts.requestOrigin) {
    findings.push({ reason: OW_REASON.REFLECT_ANY })
  }
  // 反射模式下把 null/任意源都回显
  if (opts.reflectAny === true && owLower(String(opts.requestOrigin)) === 'null') {
    findings.push({ reason: OW_REASON.NULL_ORIGIN })
  }
  return { safe: findings.length === 0, findings: findings }
}

class OriginWildcardGuard {
  auditPattern (pattern) {
    const f = auditAllowedPattern(pattern)
    return { safe: f.length === 0, findings: f }
  }

  auditResponse (opts) {
    return auditResponse(opts || {})
  }
}

module.exports = Object.freeze({
  OW_REASON: OW_REASON,
  OriginWildcardGuard: OriginWildcardGuard
})
