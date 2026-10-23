'use strict'

// sandboxframeguard.js —— iframe sandbox 标志与 allow 权限最小化守卫。
//
// 威胁模型：
//   嵌入第三方内容的 <iframe sandbox> 若配错权限等于没沙箱：
//     - 完全不给 sandbox 时第三方页面可跑脚本、弹窗、提权；
//     - allow-scripts + allow-same-origin 同时给，沙箱形同虚设（脚本能改自身属性/访问同源存储）；
//     - allow-top-navigation 让嵌框劫持顶层跳转；
//     - allow-popups-to-escape-sandbox 让弹窗逃逸沙箱；
//     - allow-forms 对纯展示内容是多余权限。
//   本模块审计 sandbox token 集合，按嵌入用途给最小权限建议。纯字符匹配，不使用正则。

const SF2_REASON = Object.freeze({
  NO_SANDBOX: 'frame-embedding-third-party-without-sandbox',
  SCRIPTS_PLUS_SAMEORIGIN: 'sandbox-allows-scripts-and-same-origin-together',
  TOP_NAVIGATION: 'sandbox-allows-top-navigation-for-embedded-content',
  POPUPS_ESCAPE: 'sandbox-popups-to-escape-sandbox-granted',
  UNNEEDED_FORMS: 'sandbox-allows-forms-for-display-only-frame',
  UNKNOWN_TOKEN: 'sandbox-token-unrecognized'
})

const KNOWN_TOKENS = [
  'allow-forms', 'allow-modals', 'allow-orientation-lock', 'allow-pointer-lock',
  'allow-popups', 'allow-popups-to-escape-sandbox', 'allow-presentation',
  'allow-same-origin', 'allow-scripts', 'allow-top-navigation',
  'allow-top-navigation-by-user-activation', 'allow-downloads', 'allow-storage-access-by-user-activation'
]

function sfIsSpace (c) {
  return c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f' || c === '\v'
}

function sfTokens (sandboxAttr) {
  if (sandboxAttr === null || sandboxAttr === undefined) return null
  const raw = String(sandboxAttr)
  const out = []
  let i = 0
  while (i < raw.length) {
    while (i < raw.length && sfIsSpace(raw[i])) i++
    const start = i
    while (i < raw.length && !sfIsSpace(raw[i])) i++
    if (i > start) out.push(raw.slice(start, i))
  }
  if (out.length === 0 && raw.trim() === '') return [] // 纯空白/空字符串 = 全限制
  return out
}

class SandboxFrameGuard {
  // in: { thirdParty:bool, sandbox:属性值或null, purpose:'display'|'widget' }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const tokens = sfTokens(inp.sandbox)
    if (tokens === null) {
      if (inp.thirdParty === true) findings.push({ reason: SF2_REASON.NO_SANDBOX })
      return { safe: !inp.thirdParty, findings: findings, tokens: [] }
    }
    const set = new Set(tokens)
    for (const t of tokens) {
      if (KNOWN_TOKENS.indexOf(t) < 0) findings.push({ reason: SF2_REASON.UNKNOWN_TOKEN, detail: t })
    }
    if (set.has('allow-scripts') && set.has('allow-same-origin')) {
      findings.push({ reason: SF2_REASON.SCRIPTS_PLUS_SAMEORIGIN })
    }
    if (set.has('allow-top-navigation')) findings.push({ reason: SF2_REASON.TOP_NAVIGATION })
    if (set.has('allow-popups-to-escape-sandbox')) findings.push({ reason: SF2_REASON.POPUPS_ESCAPE })
    if (inp.purpose === 'display' && set.has('allow-forms')) {
      findings.push({ reason: SF2_REASON.UNNEEDED_FORMS })
    }
    return { safe: findings.length === 0, findings: findings, tokens: tokens }
  }
}

module.exports = Object.freeze({
  SF2_REASON: SF2_REASON,
  KNOWN_TOKENS: KNOWN_TOKENS,
  sfTokens: sfTokens,
  SandboxFrameGuard: SandboxFrameGuard
})
