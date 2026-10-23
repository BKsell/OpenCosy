'use strict'

// xframeoptionsguard.js —— X-Frame-Options（点击劫持嵌套控制）守卫。
//
// 威胁模型：
//   X-Frame-Options 决定本页能否被 <frame>/<iframe>/<object> 嵌套。缺失或宽松会导致点击劫持：
//   攻击者把敏感页透明地叠在诱导 UI 上，劫持用户点击。常见错配：
//     - 头缺失：默认允许任意站点嵌套；
//     - ALLOW-FROM <uri>：该指令在现代浏览器中已基本不被支持，且只支持单一来源，极易误用；
//     - 多个 XFO 头 / 逗号多值：不同浏览器取法不一（拒绝或取其一），形成绕过窗口；
//     - 值大小写或空白异常、夹带引号/控制字符：可能被判定为无效而整体忽略。
//
// 建议现代页面优先用 CSP frame-ancestors；XFO 作为旧浏览器兜底，本模块同时支持
// 评估 XFO 值与 frame-ancestors 是否一致（由调用方传入 CSP 结果）。

const XFO_HEADER = 'x-frame-options'

const XFO_REASON = Object.freeze({
  MISSING: 'xfo-missing',
  EMPTY: 'xfo-empty',
  INVALID_VALUE: 'xfo-invalid-value',
  ALLOW_FROM_DEPRECATED: 'xfo-allow-from-deprecated',
  MULTIPLE_VALUES: 'xfo-multiple-values',
  CONTROL_CHAR: 'xfo-control-char',
  CONTRADICTS_CSP: 'xfo-contradicts-frame-ancestors'
})

const XFO_MODE = Object.freeze({
  DENY: 'DENY',
  SAMEORIGIN: 'SAMEORIGIN',
  ALLOW_FROM: 'ALLOW-FROM'
})

function defaultXfoPolicy () {
  return {
    preferred: XFO_MODE.SAMEORIGIN,
    rejectAllowFrom: true,
    rejectControlChars: true
  }
}

function xfoHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class XFrameOptionsGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultXfoPolicy(), policy || {})
  }

  // 传入 XFO 头值（单个字符串；若有重复头，调用方应把数组先传入 evaluateMultiple）。
  // frameAncestors：可选，'none'/'self'/来源集合等，用于一致性比对（简单标记）。
  evaluate (headerValue, frameAncestors) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: XFO_REASON.MISSING })
      return { safe: false, mode: null, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim()
    if (value === '') {
      findings.push({ reason: XFO_REASON.EMPTY })
      return { safe: false, mode: null, findings }
    }
    if (pol.rejectControlChars && xfoHasControlChar(raw)) {
      findings.push({ reason: XFO_REASON.CONTROL_CHAR })
    }
    // 逗号多值视为冲突。
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: XFO_REASON.MULTIPLE_VALUES })
    }

    const upper = value.toUpperCase()
    let mode = null
    if (upper === XFO_MODE.DENY) {
      mode = XFO_MODE.DENY
    } else if (upper === XFO_MODE.SAMEORIGIN) {
      mode = XFO_MODE.SAMEORIGIN
    } else if (upper.indexOf('ALLOW-FROM') === 0) {
      mode = XFO_MODE.ALLOW_FROM
      findings.push({ reason: XFO_REASON.ALLOW_FROM_DEPRECATED })
    } else {
      findings.push({ reason: XFO_REASON.INVALID_VALUE, value: value })
    }

    // 与 frame-ancestors 的强一致性：XFO=DENY 而 CSP 允许 self/来源属矛盾。
    if (frameAncestors && mode === XFO_MODE.DENY &&
        frameAncestors !== 'none' && frameAncestors !== "'none'") {
      findings.push({ reason: XFO_REASON.CONTRADICTS_CSP })
    }

    const blocking = (!pol.rejectAllowFrom || mode !== XFO_MODE.ALLOW_FROM) &&
                     mode !== null
    return {
      safe: findings.length === 0 && blocking,
      mode: mode,
      findings: findings
    }
  }

  // 处理重复头：多于一个非空值即不可判定。
  evaluateMultiple (values, frameAncestors) {
    const list = (values || []).filter((v) => v !== null && v !== undefined && String(v).trim() !== '')
    if (list.length === 0) {
      return this.evaluate(null, frameAncestors)
    }
    if (list.length > 1) {
      const r = this.evaluate(list[0], frameAncestors)
      r.findings.push({ reason: XFO_REASON.MULTIPLE_VALUES, count: list.length })
      r.safe = false
      return r
    }
    return this.evaluate(list[0], frameAncestors)
  }
}

module.exports = Object.freeze({
  XFO_HEADER: XFO_HEADER,
  XFO_REASON: XFO_REASON,
  XFO_MODE: XFO_MODE,
  defaultXfoPolicy: defaultXfoPolicy,
  XFrameOptionsGuard: XFrameOptionsGuard
})
