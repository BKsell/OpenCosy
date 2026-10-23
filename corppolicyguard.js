'use strict'

// corppolicyguard.js —— Cross-Origin-Resource-Policy（CORP）守卫。
//
// 威胁模型：
//   CORP 限制一个资源能被哪些来源的文档/worker 加载，是 Spectre 类跨源读取与跨源包含攻击的
//   重要缓解。缺失时跨源文档默认仍可 <img>/<script>/fetch 该资源（取决于类型）。错配：
//     - 缺失：没有跨源加载约束；
//     - cross-origin：允许任意跨源加载（对敏感用户数据应避免，至少要 same-origin）；
//     - 拼写错误值：头被忽略，等于没设；
//     - 逗号多值 / 控制字符：解析不可靠。
//
// 对含用户私有数据的响应，推荐 same-origin；公共 CDN 静态资源才用 cross-origin。

const CORP_HEADER = 'cross-origin-resource-policy'

const CORP_MODE = Object.freeze({
  SAME_SITE: 'same-site',
  SAME_ORIGIN: 'same-origin',
  CROSS_ORIGIN: 'cross-origin'
})

const CORP_REASON = Object.freeze({
  MISSING: 'corp-missing',
  EMPTY: 'corp-empty',
  INVALID: 'corp-invalid-value',
  TOO_PERMISSIVE: 'corp-too-permissive',
  MULTIPLE: 'corp-multiple-values',
  CONTROL_CHAR: 'corp-control-char'
})

function defaultCorpPolicy () {
  return {
    // 期望的最低收紧度：'same-origin' 最严，'same-site' 次之。
    // 取值 2=same-origin, 1=same-site, 0=cross-origin；默认要求 >=2。
    minLevel: 2,
    rejectControlChars: true
  }
}

function corpLevelOf (mode) {
  if (mode === CORP_MODE.CROSS_ORIGIN) return 0
  if (mode === CORP_MODE.SAME_SITE) return 1
  if (mode === CORP_MODE.SAME_ORIGIN) return 2
  return -1
}

function corpHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class CorpPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCorpPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: CORP_REASON.MISSING })
      return { safe: false, mode: null, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim().toLowerCase()
    if (value === '') {
      findings.push({ reason: CORP_REASON.EMPTY })
      return { safe: false, mode: null, findings }
    }
    if (pol.rejectControlChars && corpHasControlChar(raw)) {
      findings.push({ reason: CORP_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: CORP_REASON.MULTIPLE })
    }
    const single = value.split(',')[0].trim()
    const level = corpLevelOf(single)
    if (level < 0) {
      findings.push({ reason: CORP_REASON.INVALID, value: single })
      return { safe: false, mode: null, findings }
    }
    if (level < pol.minLevel) {
      findings.push({ reason: CORP_REASON.TOO_PERMISSIVE, mode: single })
    }
    return { safe: findings.length === 0, mode: single, level: level, findings }
  }
}

module.exports = Object.freeze({
  CORP_HEADER: CORP_HEADER,
  CORP_MODE: CORP_MODE,
  CORP_REASON: CORP_REASON,
  defaultCorpPolicy: defaultCorpPolicy,
  CorpPolicyGuard: CorpPolicyGuard
})
