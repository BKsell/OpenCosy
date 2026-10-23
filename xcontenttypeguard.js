'use strict'

// xcontenttypeguard.js —— X-Content-Type-Options: nosniff 守卫。
//
// 威胁模型：
//   缺少 nosniff 时浏览器会做 MIME 嗅探：把实际是 HTML/JS 的响应当成声明的 text/plain 或图片，
//   仍可能被当作脚本/文档执行，构成 MIME confusion XSS（尤其在用户上传内容可被同源访问时）。
// 常见错配：
//   - 头缺失；
//   - 值不是精确的 "nosniff"（如 "nosniff, noopen"、"no-sniff"、前后缀垃圾）；
//   - 多个头 / 逗号多值；
//   - 大小写不敏感是允许的，但夹带控制字符应拒绝。
//
// 本模块对单一来源（如下载、上传回显、静态资源）的响应头做强制校验。

const XCTO_HEADER = 'x-content-type-options'
const NOSNIFF = 'nosniff'

const XCTO_REASON = Object.freeze({
  MISSING: 'xcto-missing',
  EMPTY: 'xcto-empty',
  NOT_NOSNIFF: 'xcto-not-nosniff',
  MULTIPLE_VALUES: 'xcto-multiple-values',
  CONTROL_CHAR: 'xcto-control-char'
})

function defaultXctoPolicy () {
  return { rejectControlChars: true }
}

function xctoHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class XContentTypeOptionsGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultXctoPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: XCTO_REASON.MISSING })
      return { safe: false, nosniff: false, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim()
    if (value === '') {
      findings.push({ reason: XCTO_REASON.EMPTY })
      return { safe: false, nosniff: false, findings }
    }
    // 控制字符要在 trim 之前检测，否则首尾的 CRLF/NUL 会被 trim 掩盖（头走私面）。
    if (this.policy.rejectControlChars && xctoHasControlChar(raw)) {
      findings.push({ reason: XCTO_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: XCTO_REASON.MULTIPLE_VALUES })
    }
    const isNosniff = value.toLowerCase() === NOSNIFF
    if (!isNosniff) {
      findings.push({ reason: XCTO_REASON.NOT_NOSNIFF, value: value })
    }
    return { safe: findings.length === 0, nosniff: isNosniff, findings }
  }

  evaluateHeaders (headers) {
    const map = headers || {}
    const names = Object.keys(map)
    for (let i = 0; i < names.length; i++) {
      if (names[i].toLowerCase() === XCTO_HEADER) {
        return this.evaluate(map[names[i]])
      }
    }
    return this.evaluate(null)
  }
}

module.exports = Object.freeze({
  XCTO_HEADER: XCTO_HEADER,
  NOSNIFF: NOSNIFF,
  XCTO_REASON: XCTO_REASON,
  defaultXctoPolicy: defaultXctoPolicy,
  XContentTypeOptionsGuard: XContentTypeOptionsGuard
})
