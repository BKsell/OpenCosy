'use strict'

// originagentclusterguard.js —— Origin-Agent-Cluster 响应头守卫。
//
// 威胁模型：
//   Origin-Agent-Cluster: ?1 让浏览器为该源分配独立的 agent cluster（进程/事件循环隔离更彻底），
//   减小跨源脚本共享与进程级侧信道面。关键资源（尤其希望跨源隔离的应用）应显式启用。
//   错配：值不是精确的 "?1"（如 true/1），头被忽略；缺失（未请求隔离）；控制字符。
//
// 注意：启用 OAC 后 document.domain 不可修改，这正是想要的隔离效果。

const OAC_HEADER = 'origin-agent-cluster'
const OAC_ENABLED = '?1'

const OAC_REASON = Object.freeze({
  MISSING: 'oac-missing',
  EMPTY: 'oac-empty',
  INVALID: 'oac-invalid-value',
  DISABLED: 'oac-disabled',
  MULTIPLE: 'oac-multiple-values',
  CONTROL_CHAR: 'oac-control-char'
})

function defaultOacPolicy () {
  return { required: true, rejectControlChars: true }
}

function oacHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class OriginAgentClusterGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultOacPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      if (this.policy.required) findings.push({ reason: OAC_REASON.MISSING })
      return { safe: !this.policy.required, enabled: false, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim()
    if (value === '') {
      findings.push({ reason: OAC_REASON.EMPTY })
      return { safe: false, enabled: false, findings }
    }
    if (this.policy.rejectControlChars && oacHasControlChar(raw)) {
      findings.push({ reason: OAC_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) findings.push({ reason: OAC_REASON.MULTIPLE })
    if (value === OAC_ENABLED) {
      return { safe: findings.length === 0, enabled: true, findings }
    }
    if (value === '?0') {
      findings.push({ reason: OAC_REASON.DISABLED })
    } else {
      findings.push({ reason: OAC_REASON.INVALID, value: value })
    }
    return { safe: false, enabled: false, findings }
  }
}

module.exports = Object.freeze({
  OAC_HEADER: OAC_HEADER,
  OAC_ENABLED: OAC_ENABLED,
  OAC_REASON: OAC_REASON,
  defaultOacPolicy: defaultOacPolicy,
  OriginAgentClusterGuard: OriginAgentClusterGuard
})
