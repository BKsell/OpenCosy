'use strict'

// referrerpolicyguard.js —— Referrer-Policy 响应头守卫。
//
// 威胁模型：
//   默认情况下跨站导航/资源加载会把完整 URL（可能含路径里的 token、会话 id）放进 Referer，
//   泄露给第三方。宽松策略（unsafe-url / no-referrer-when-downgrade）在 HTTPS→HTTP 或跨站
//   时仍会泄露完整 URL。错配：
//     - 头缺失：退回浏览器默认（多为 strict-origin-when-cross-origin，但旧版本更宽松）；
//     - unsafe-url：任何情况都发完整 URL；
//     - no-referrer-when-downgrade / origin-when-cross-origin：跨站仍可能带 origin 或路径；
//     - 逗号多值：取最后一个可识别值，易被注入头覆盖；
//     - 未知/拼写错误策略：被忽略，退回默认，形成"以为收紧了其实没有"。
//
// 推荐基线 strict-origin-when-cross-origin 或更严的 no-referrer。

const REFERRER_HEADER = 'referrer-policy'

const RP_REASON = Object.freeze({
  MISSING: 'rp-missing',
  EMPTY: 'rp-empty',
  UNSAFE_URL: 'rp-unsafe-url',
  LEGACY_DOWNGRADE: 'rp-legacy-downgrade-leak',
  CROSS_ORIGIN_LEAK: 'rp-cross-origin-leak',
  UNKNOWN_TOKEN: 'rp-unknown-token',
  CONTROL_CHAR: 'rp-control-char'
})

// 按"泄露强度"从宽到严排序，便于比较。
const RP_TOKENS = Object.freeze({
  'unsafe-url': { rank: 0 },
  'no-referrer-when-downgrade': { rank: 1 },
  'origin-when-cross-origin': { rank: 2 },
  'origin': { rank: 3 },
  'same-origin': { rank: 4 },
  'strict-origin': { rank: 5 },
  'strict-origin-when-cross-origin': { rank: 6 },
  'no-referrer': { rank: 7 }
})

function defaultReferrerPolicy () {
  return {
    minRank: 6, // 至少 strict-origin-when-cross-origin
    rejectControlChars: true
  }
}

function rpHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

// 解析逗号分隔的候选策略；浏览器取最后一个可识别值。
function parseReferrerTokens (value) {
  const tokens = []
  const unknown = []
  const parts = String(value).split(',')
  for (let i = 0; i < parts.length; i++) {
    const t = parts[i].trim().toLowerCase()
    if (t === '') continue
    if (RP_TOKENS[t]) {
      tokens.push(t)
    } else {
      unknown.push(t)
    }
  }
  return { tokens: tokens, unknown: unknown }
}

class ReferrerPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultReferrerPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: RP_REASON.MISSING })
      return { safe: false, effective: null, findings }
    }
    const raw = String(headerValue)
    if (raw.trim() === '') {
      findings.push({ reason: RP_REASON.EMPTY })
      return { safe: false, effective: null, findings }
    }
    if (pol.rejectControlChars && rpHasControlChar(raw)) {
      findings.push({ reason: RP_REASON.CONTROL_CHAR })
    }
    const parsed = parseReferrerTokens(raw)
    parsed.unknown.forEach((t) => findings.push({ reason: RP_REASON.UNKNOWN_TOKEN, token: t }))

    if (parsed.tokens.length === 0) {
      return { safe: false, effective: null, findings }
    }
    const effective = parsed.tokens[parsed.tokens.length - 1]
    const info = RP_TOKENS[effective]

    if (effective === 'unsafe-url') {
      findings.push({ reason: RP_REASON.UNSAFE_URL })
    } else if (effective === 'no-referrer-when-downgrade') {
      findings.push({ reason: RP_REASON.LEGACY_DOWNGRADE })
    } else if (info.rank < 6) {
      findings.push({ reason: RP_REASON.CROSS_ORIGIN_LEAK, effective: effective })
    }

    return {
      safe: findings.length === 0 && info.rank >= pol.minRank,
      effective: effective,
      findings: findings
    }
  }
}

module.exports = Object.freeze({
  REFERRER_HEADER: REFERRER_HEADER,
  RP_REASON: RP_REASON,
  RP_TOKENS: RP_TOKENS,
  defaultReferrerPolicy: defaultReferrerPolicy,
  parseReferrerTokens: parseReferrerTokens,
  ReferrerPolicyGuard: ReferrerPolicyGuard
})
