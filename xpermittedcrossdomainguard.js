'use strict'

// xpermittedcrossdomainguard.js —— X-Permitted-Cross-Domain-Policies 守卫。
//
// 威胁模型：
//   Adobe Flash / PDF 客户端会读取 crossdomain.xml 决定是否允许跨域读取本域数据。响应头
//   X-Permitted-Cross-Domain-Policies 控制主策略文件是否被采纳。危险取值：
//     - none 之外的值（all / by-content-type / master-only / by-ftp-filename）都可能放行
//       跨域策略文件，遗留客户端可借此跨域读取带 Cookie 的数据；
//     - 缺失：某些旧客户端回退为允许查找默认 crossdomain.xml；
//     - 非法值：行为依实现而定。
//
// 不使用 Flash/PDF 跨域能力的现代站点应固定为 none。

const XPCDP_HEADER = 'x-permitted-cross-domain-policies'

const XPCDP_MODE = Object.freeze({
  NONE: 'none',
  MASTER_ONLY: 'master-only',
  BY_CONTENT_TYPE: 'by-content-type',
  BY_FTP_FILENAME: 'by-ftp-filename',
  ALL: 'all'
})

const XPCDP_REASON = Object.freeze({
  MISSING: 'xpcdp-missing',
  EMPTY: 'xpcdp-empty',
  PERMISSIVE: 'xpcdp-permissive',
  INVALID: 'xpcdp-invalid-value',
  MULTIPLE: 'xpcdp-multiple-values',
  CONTROL_CHAR: 'xpcdp-control-char'
})

const XPCDP_SAFE = Object.freeze({ none: true })

function defaultXpcdpPolicy () {
  return { required: true, rejectControlChars: true }
}

function xpcdpHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class XPermittedCrossDomainGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultXpcdpPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      if (this.policy.required) findings.push({ reason: XPCDP_REASON.MISSING })
      return { safe: !this.policy.required, mode: null, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim().toLowerCase()
    if (value === '') {
      findings.push({ reason: XPCDP_REASON.EMPTY })
      return { safe: false, mode: null, findings }
    }
    if (this.policy.rejectControlChars && xpcdpHasControlChar(raw)) {
      findings.push({ reason: XPCDP_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: XPCDP_REASON.MULTIPLE })
    }
    const single = value.split(',')[0].trim()
    const known = Object.keys(XPCDP_MODE).some((k) => XPCDP_MODE[k] === single)
    if (!known) {
      findings.push({ reason: XPCDP_REASON.INVALID, value: single })
      return { safe: false, mode: null, findings }
    }
    if (!XPCDP_SAFE[single]) {
      findings.push({ reason: XPCDP_REASON.PERMISSIVE, mode: single })
    }
    return { safe: findings.length === 0, mode: single, findings }
  }
}

module.exports = Object.freeze({
  XPCDP_HEADER: XPCDP_HEADER,
  XPCDP_MODE: XPCDP_MODE,
  XPCDP_REASON: XPCDP_REASON,
  defaultXpcdpPolicy: defaultXpcdpPolicy,
  XPermittedCrossDomainGuard: XPermittedCrossDomainGuard
})
