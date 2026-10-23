'use strict'

// trustedtypesguard.js —— CSP Trusted Types 指令守卫。
//
// 威胁模型：
//   DOM XSS 的根源是把字符串直接塞给 innerHTML / document.write / eval 汇点。Trusted Types
//   通过 CSP 强制这些汇点只接受策略对象：
//     require-trusted-types-for 'script';
//   配套 trusted-types <policyName...> [allow-duplicates] [default] 声明允许的策略。
// 问题：
//     - 完全没有 require-trusted-types-for：DOM 汇点不设防；
//     - 写了但值不是精确的 'script'：整条无效；
//     - trusted-types 用通配 "*"：等于不限制策略，削弱防线；
//     - 重复/拼写错误指令；
//   本模块解析一段 CSP 文本，给出 Trusted Types 相关结论。纯字符解析。

const TT_REASON = Object.freeze({
  REQUIRE_MISSING: 'tt-require-trusted-types-missing',
  REQUIRE_BAD_VALUE: 'tt-require-bad-value',
  WILDCARD_POLICY: 'tt-wildcard-policy',
  NO_POLICY_DECLARED: 'tt-no-policy-declared',
  ALLOW_DUPLICATES: 'tt-allow-duplicates',
  CONTROL_CHAR: 'tt-control-char'
})

const TT_DIRECTIVE = 'require-trusted-types-for'
const TT_POLICY_DIRECTIVE = 'trusted-types'

function defaultTtPolicy () {
  return {
    requireEnforced: true,
    rejectWildcard: true,
    rejectAllowDuplicates: false,
    rejectControlChars: true
  }
}

function ttHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1F || c === 0x7F) return true
  }
  return false
}

function ttTokens (s) {
  const out = []
  let cur = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i)
    if (c === ' ' || c === '\t') { if (cur !== '') { out.push(cur); cur = '' } } else cur += c
  }
  if (cur !== '') out.push(cur)
  return out
}

// 把 CSP 文本拆成 { 指令名(小写): 原始值串 }。重复指令保留计数。
function ttParseCsp (csp) {
  const map = {}
  let requireCount = 0
  let policyCount = 0
  const parts = String(csp || '').split(';')
  parts.forEach((seg) => {
    const t = ttTokens(seg)
    if (t.length === 0) return
    const name = t[0].toLowerCase()
    if (name === TT_DIRECTIVE) requireCount++
    if (name === TT_POLICY_DIRECTIVE) policyCount++
    if (!map[name]) map[name] = { value: t.slice(1), count: 0 }
    map[name].count++
  })
  return { directives: map, requireCount: requireCount, policyCount: policyCount }
}

class TrustedTypesGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultTtPolicy(), policy || {})
  }

  evaluate (csp) {
    const pol = this.policy
    const findings = []
    const raw = String(csp || '')
    if (pol.rejectControlChars && ttHasControlChar(raw)) {
      findings.push({ reason: TT_REASON.CONTROL_CHAR })
    }
    const parsed = ttParseCsp(raw)
    const req = parsed.directives[TT_DIRECTIVE]
    if (!req) {
      if (pol.requireEnforced) findings.push({ reason: TT_REASON.REQUIRE_MISSING })
      return { safe: findings.length === 0, enforced: false, findings }
    }
    // 合法值恰好是一个 'script'（带不带引号规范要求带引号，浏览器接受 script）。
    const vals = req.value
    const norm = vals.map((v) => (v === "'script'" ? 'script' : v))
    if (norm.length !== 1 || norm[0] !== 'script') {
      findings.push({ reason: TT_REASON.REQUIRE_BAD_VALUE, value: vals.join(' ') })
    }
    const polDecl = parsed.directives[TT_POLICY_DIRECTIVE]
    if (polDecl) {
      const tokens = polDecl.value
      if (tokens.indexOf('*') >= 0 && pol.rejectWildcard) {
        findings.push({ reason: TT_REASON.WILDCARD_POLICY })
      }
      if (tokens.indexOf('allow-duplicates') >= 0 && pol.rejectAllowDuplicates) {
        findings.push({ reason: TT_REASON.ALLOW_DUPLICATES })
      }
      const named = tokens.filter((t) => t !== 'allow-duplicates' && t !== 'default' && t !== '*')
      if (named.length === 0 && tokens.indexOf('*') < 0) {
        findings.push({ reason: TT_REASON.NO_POLICY_DECLARED })
      }
    }
    return {
      safe: findings.length === 0,
      enforced: true,
      policies: polDecl ? polDecl.value : [],
      findings: findings
    }
  }
}

module.exports = Object.freeze({
  TT_REASON: TT_REASON,
  TT_DIRECTIVE: TT_DIRECTIVE,
  TT_POLICY_DIRECTIVE: TT_POLICY_DIRECTIVE,
  defaultTtPolicy: defaultTtPolicy,
  ttParseCsp: ttParseCsp,
  TrustedTypesGuard: TrustedTypesGuard
})
