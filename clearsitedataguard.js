'use strict'

// clearsitedataguard.js —— Clear-Site-Data 响应头守卫。
//
// 威胁模型：
//   Clear-Site-Data 让浏览器删除该源存储（cache/cookies/storage/executionContexts）。
//   配置要点与风险：
//     - 仅应在 HTTPS 响应上发送（浏览器在非安全上下文忽略，属于配置无效）；
//     - 指令值必须带引号（"cache"），裸写 cache 非法被忽略，造成"以为清了其实没清"；
//     - 通配 "*" 会清除全部，登出/注销端点才适合；普通页面误用会误删用户数据；
//     - 重复/未知指令需暴露；执行 executionContexts 会重载页面，需感知。

const CSD_HEADER = 'clear-site-data'

const CSD_DIRECTIVE = Object.freeze({
  CACHE: 'cache',
  COOKIES: 'cookies',
  STORAGE: 'storage',
  EXECUTION: 'executionContexts',
  WILDCARD: '*',
  CLIENT_HINTS: 'clientHints'
})

const CSD_REASON = Object.freeze({
  EMPTY: 'csd-empty',
  UNQUOTED_DIRECTIVE: 'csd-unquoted-directive',
  UNKNOWN_DIRECTIVE: 'csd-unknown-directive',
  WILDCARD_MIXED: 'csd-wildcard-mixed-with-others',
  INSECURE_CONTEXT: 'csd-insecure-context',
  CONTROL_CHAR: 'csd-control-char'
})

const CSD_KNOWN = Object.freeze({
  cache: true, cookies: true, storage: true,
  executioncontexts: true, clienthints: true, '*': true
})

function defaultCsdPolicy () {
  return { rejectControlChars: true, rejectUnknown: false, rejectUnquoted: true }
}

function csdIsBareToken (s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const isLetter = (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
    if (!isLetter && s.charAt(i) !== '*') return false
  }
  return true
}

function csdHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1F || c === 0x7F) return true
  }
  return false
}

class ClearSiteDataGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCsdPolicy(), policy || {})
  }

  // value：Clear-Site-Data 头值；secure：响应是否走 HTTPS。
  evaluate (headerValue, secure) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      return { safe: true, present: false, directives: [], findings }
    }
    const raw = String(headerValue)
    if (raw.trim() === '') {
      findings.push({ reason: CSD_REASON.EMPTY })
      return { safe: false, present: true, findings }
    }
    if (pol.rejectControlChars && csdHasControlChar(raw)) {
      findings.push({ reason: CSD_REASON.CONTROL_CHAR })
    }
    const dirs = []
    let wildcard = false
    const parts = raw.split(',')
    for (let i = 0; i < parts.length; i++) {
      const tok = parts[i].trim()
      if (tok === '') continue
      let name = tok
      const q = tok.length >= 2 && tok.charAt(0) === '"' && tok.charAt(tok.length - 1) === '"'
      if (q) {
        name = tok.slice(1, tok.length - 1)
      } else if (pol.rejectUnquoted && csdIsBareToken(tok)) {
        findings.push({ reason: CSD_REASON.UNQUOTED_DIRECTIVE, token: tok })
      }
      const lower = name.toLowerCase()
      dirs.push(lower)
      if (lower === '*') wildcard = true
      if (!CSD_KNOWN[lower]) {
        findings.push({ reason: CSD_REASON.UNKNOWN_DIRECTIVE, directive: lower })
      }
    }
    if (wildcard && dirs.length > 1) {
      findings.push({ reason: CSD_REASON.WILDCARD_MIXED })
    }
    if (secure === false) {
      findings.push({ reason: CSD_REASON.INSECURE_CONTEXT })
    }
    return { safe: findings.length === 0, present: true, directives: dirs, wildcard: wildcard, findings: findings }
  }
}

module.exports = Object.freeze({
  CSD_HEADER: CSD_HEADER,
  CSD_DIRECTIVE: CSD_DIRECTIVE,
  CSD_REASON: CSD_REASON,
  defaultCsdPolicy: defaultCsdPolicy,
  ClearSiteDataGuard: ClearSiteDataGuard
})
