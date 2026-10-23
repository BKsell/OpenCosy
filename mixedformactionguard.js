'use strict'

// mixedformactionguard.js —— HTTPS 页面表单提交到 HTTP（混合表单/降级提交）守卫。
//
// 威胁模型：
//   页面本身是 https，但 <form action="http://..."> 会把用户填写的账号、密码、信用卡明文提交，
//   可被中间人窃取/篡改。即使表单页看起来有锁，提交动作是明文。变体：
//     - action 为 http://；
//     - action 为协议相对 //host 且当前页面其实是 http（这里按 action 解析后的 scheme 判断）；
//     - 提交目标主机与页面不同（跨站提交，结合凭据更敏感）。
//   纯字符解析 action，不使用正则。

const MFA_REASON = Object.freeze({
  FORM_TO_HTTP: 'https-page-form-submits-to-plaintext-http',
  ACTION_PROTOCOL_RELATIVE: 'form-action-is-protocol-relative',
  CROSS_ORIGIN_FORM: 'form-submits-to-a-different-origin',
  NON_HTTP_SCHEME: 'form-action-uses-non-http-scheme'
})

const SAFE_FORM_SCHEMES = ['http', 'https']

function mfaLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function mfaNoColon (s) {
  return s.length > 0 && s[s.length - 1] === ':' ? s.slice(0, -1) : s
}

function mfaIndexAny (s, chars) {
  for (let i = 0; i < s.length; i++) if (chars.indexOf(s[i]) >= 0) return i
  return -1
}

function mfaParseAction (action, pageScheme) {
  const a = String(action || '').trim()
  const page = mfaNoColon(mfaLower(String(pageScheme || '')))
  if (a.indexOf('//') === 0 || a.indexOf('\\\\') === 0) {
    return { scheme: page || 'http', host: mfaHost(a.slice(2)), protoRelative: true }
  }
  const colon = a.indexOf(':')
  const firstSeg = mfaIndexAny(a, ['/', '?', '#'])
  if (colon >= 0 && (firstSeg < 0 || colon < firstSeg)) {
    const scheme = mfaNoColon(mfaLower(a.slice(0, colon + 1)))
    const rest = a.slice(colon + 3)
    return { scheme: scheme, host: mfaHost(rest), protoRelative: false }
  }
  // 相对路径：提交回当前页源
  return { scheme: page, host: null, protoRelative: false, relative: true }
}

function mfaHost (rest) {
  let h = String(rest)
  const end = mfaIndexAny(h, ['/', '?', '#'])
  if (end >= 0) h = h.slice(0, end)
  const pc = h.indexOf(':')
  if (pc >= 0) h = h.slice(0, pc)
  return mfaLower(h)
}

class MixedFormActionGuard {
  // in: { pageScheme:'https', pageHost, action, carriesPassword }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const parsed = mfaParseAction(inp.action, inp.pageScheme)
    const pageScheme = mfaNoColon(mfaLower(String(inp.pageScheme || '')))
    if (parsed.protoRelative) findings.push({ reason: MFA_REASON.ACTION_PROTOCOL_RELATIVE })
    if (parsed.scheme && SAFE_FORM_SCHEMES.indexOf(parsed.scheme) < 0) {
      findings.push({ reason: MFA_REASON.NON_HTTP_SCHEME, detail: parsed.scheme })
    }
    if (pageScheme === 'https' && parsed.scheme === 'http') {
      findings.push({ reason: MFA_REASON.FORM_TO_HTTP })
    }
    if (parsed.host && inp.pageHost && parsed.host !== mfaLower(String(inp.pageHost))) {
      findings.push({ reason: MFA_REASON.CROSS_ORIGIN_FORM, detail: parsed.host })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  MFA_REASON: MFA_REASON,
  mfaParseAction: mfaParseAction,
  MixedFormActionGuard: MixedFormActionGuard
})
