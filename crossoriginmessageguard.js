'use strict'

// crossoriginmessageguard.js —— window.postMessage 的 targetOrigin 与来源白名单守卫。
//
// 威胁模型：
//   内嵌页面、扩展 iframe、帮助面板之间用 postMessage 通信。两类错误导致跨源数据泄露 / 越权：
//     - 发送时 targetOrigin 用 '*'：若目标窗口发生过导航（被诱导到攻击者页面），敏感消息就发出去了；
//     - 接收时不校验 event.origin（或用 endsWith / includes 做宽松匹配），任何页面都能伪造指令。
//   与既有 postmessagetargetguard 的区别：本模块给出"发送目标 + 接收来源白名单"的组合判定与
//   精确匹配助手，供需要双向消息的面板复用。纯字符判定，不使用正则。

const CM_REASON = Object.freeze({
  WILDCARD_TARGET: 'postmessage-targetorigin-is-wildcard',
  ORIGIN_NOT_ALLOWED: 'postmessage-event-origin-not-in-allowlist',
  EMPTY_ORIGIN: 'postmessage-origin-empty-or-null',
  DATA_NOT_OBJECT: 'postmessage-payload-not-structured-object'
})

function cmLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

class CrossOriginMessageGuard {
  // allowedOrigins: 精确来源数组（小写比较）
  constructor (allowedOrigins) {
    this.allow = new Set((allowedOrigins || []).map(cmLower))
  }

  auditSend (targetOrigin, data) {
    const findings = []
    if (targetOrigin === '*' || targetOrigin === undefined || targetOrigin === null) {
      findings.push({ reason: CM_REASON.WILDCARD_TARGET })
    } else if (!targetOrigin) {
      findings.push({ reason: CM_REASON.EMPTY_ORIGIN })
    }
    if (data === null || typeof data !== 'object') {
      findings.push({ reason: CM_REASON.DATA_NOT_OBJECT })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  auditReceive (event) {
    const e = event || {}
    const findings = []
    const origin = e.origin === undefined || e.origin === null ? '' : String(e.origin)
    if (!origin || cmLower(origin) === 'null') {
      findings.push({ reason: CM_REASON.EMPTY_ORIGIN })
    } else if (!this.allow.has(cmLower(origin))) {
      findings.push({ reason: CM_REASON.ORIGIN_NOT_ALLOWED, detail: origin })
    }
    if (e.data === null || typeof e.data !== 'object' || Array.isArray(e.data)) {
      findings.push({ reason: CM_REASON.DATA_NOT_OBJECT })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  isOriginAllowed (origin) {
    return this.allow.has(cmLower(String(origin)))
  }
}

module.exports = Object.freeze({
  CM_REASON: CM_REASON,
  CrossOriginMessageGuard: CrossOriginMessageGuard
})
