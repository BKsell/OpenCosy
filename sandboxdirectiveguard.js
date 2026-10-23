'use strict'

// sandboxdirectiveguard.js —— CSP sandbox 指令 / <iframe sandbox> 令牌组合守卫。
//
// 威胁模型：
//   sandbox 不给任何令牌时最严（同源特征、脚本、表单、弹窗全部禁用）。逐令牌放开会削弱隔离，
//   其中最经典的致命组合是：
//     allow-scripts + allow-same-origin
//   被框页面既能跑脚本又处在其真实源，可自行移除自己的 sandbox 属性，等于完全绕过沙箱。
// 其它高风险点：
//     - allow-top-navigation（+ allow-top-navigation-by-user-activation）：可跳转/伪造顶层页；
//     - allow-popups-to-escape-sandbox：新窗口脱离沙箱；
//     - allow-modals / allow-forms / allow-pointer-lock / allow-popups / allow-presentation：
//       各自放开一面，需按最小权限核对；
//     - 拼写错误的令牌被忽略，造成"以为放开/收紧其实没生效"。
//
// 本模块解析令牌集并对危险组合与未知令牌给出结论。

const SB_REASON = Object.freeze({
  EMPTY_SANDBOX: 'sb-empty-value',
  SCRIPTS_WITH_SAME_ORIGIN: 'sb-allow-scripts-with-same-origin',
  TOP_NAVIGATION: 'sb-allow-top-navigation',
  POPUPS_ESCAPE: 'sb-allow-popups-to-escape-sandbox',
  UNKNOWN_TOKEN: 'sb-unknown-token',
  CONTROL_CHAR: 'sb-control-char'
})

const SB_KNOWN = Object.freeze({
  'allow-downloads': true,
  'allow-forms': true,
  'allow-modals': true,
  'allow-orientation-lock': true,
  'allow-pointer-lock': true,
  'allow-popups': true,
  'allow-popups-to-escape-sandbox': true,
  'allow-presentation': true,
  'allow-same-origin': true,
  'allow-scripts': true,
  'allow-storage-access-by-user-activation': true,
  'allow-top-navigation': true,
  'allow-top-navigation-by-user-activation': true,
  'allow-top-navigation-to-custom-protocols': true,
  'allow-downloads-without-user-activation': true
})

function defaultSandboxPolicy () {
  return {
    rejectScriptsSameOrigin: true,
    rejectTopNavigation: false,
    rejectPopupsEscape: false,
    rejectUnknownTokens: false,
    rejectControlChars: true
  }
}

function sbHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

function sbSplit (value) {
  const tokens = []
  let cur = ''
  for (let i = 0; i < value.length; i++) {
    const c = value.charAt(i)
    if (c === ' ' || c === '\t') {
      if (cur !== '') { tokens.push(cur); cur = '' }
    } else {
      cur += c
    }
  }
  if (cur !== '') tokens.push(cur)
  return tokens
}

// 解析 sandbox 值（不含 "sandbox" 关键字本身）。空串=最严。
function parseSandboxTokens (value) {
  const v = (value === null || value === undefined) ? '' : String(value)
  const raw = sbSplit(v)
  const set = {}
  const unknown = []
  raw.forEach((t) => {
    const lower = t.toLowerCase()
    if (SB_KNOWN[lower]) set[lower] = true
    else unknown.push(lower)
  })
  return { tokens: raw, set: set, unknown: unknown, fullyRestrictive: raw.length === 0 }
}

class SandboxDirectiveGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultSandboxPolicy(), policy || {})
  }

  evaluate (sandboxValue) {
    const pol = this.policy
    const findings = []
    const rawInput = (sandboxValue === null || sandboxValue === undefined) ? '' : String(sandboxValue)
    if (pol.rejectControlChars && sbHasControlChar(rawInput)) {
      findings.push({ reason: SB_REASON.CONTROL_CHAR })
    }
    const parsed = parseSandboxTokens(rawInput)

    if (pol.rejectScriptsSameOrigin &&
        parsed.set['allow-scripts'] && parsed.set['allow-same-origin']) {
      findings.push({ reason: SB_REASON.SCRIPTS_WITH_SAME_ORIGIN })
    }
    if ((pol.rejectTopNavigation) &&
        (parsed.set['allow-top-navigation'] ||
         parsed.set['allow-top-navigation-by-user-activation'] ||
         parsed.set['allow-top-navigation-to-custom-protocols'])) {
      findings.push({ reason: SB_REASON.TOP_NAVIGATION })
    }
    if (pol.rejectPopupsEscape && parsed.set['allow-popups-to-escape-sandbox']) {
      findings.push({ reason: SB_REASON.POPUPS_ESCAPE })
    }
    if (pol.rejectUnknownTokens) {
      parsed.unknown.forEach((t) => findings.push({ reason: SB_REASON.UNKNOWN_TOKEN, token: t }))
    }

    return {
      safe: findings.length === 0,
      fullyRestrictive: parsed.fullyRestrictive,
      tokens: parsed.tokens,
      unknown: parsed.unknown,
      findings: findings
    }
  }
}

module.exports = Object.freeze({
  SB_REASON: SB_REASON,
  SB_KNOWN: SB_KNOWN,
  defaultSandboxPolicy: defaultSandboxPolicy,
  parseSandboxTokens: parseSandboxTokens,
  SandboxDirectiveGuard: SandboxDirectiveGuard
})
