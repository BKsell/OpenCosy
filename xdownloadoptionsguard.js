'use strict'

// xdownloadoptionsguard.js —— X-Download-Options 遗留头守卫（IE/旧 Edge 下载）。
//
// 威胁模型：
//   旧 IE 下载 HTML 文件后默认可能在下载区"打开"，该文件继承来源站域上下文，可读取下载来源页
//   可能写入的标记 / 触发同源脚本。X-Download-Options: noopen 强制下载文件不能在原站点上下文
//   直接打开。错配：缺失（旧引擎默认允许）、值不是 noopen、多值/控制字符。
//
// 现代浏览器已忽略此头，但作为面向旧引擎下载链路的纵深防御仍应在文件下载响应上设置。

const XDO_HEADER = 'x-download-options'
const XDO_NOOPEN = 'noopen'

const XDO_REASON = Object.freeze({
  MISSING: 'xdo-missing',
  EMPTY: 'xdo-empty',
  NOT_NOOPEN: 'xdo-not-noopen',
  MULTIPLE: 'xdo-multiple-values',
  CONTROL_CHAR: 'xdo-control-char'
})

function defaultXdoPolicy () {
  return { required: true, rejectControlChars: true }
}

function xdoHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

class XDownloadOptionsGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultXdoPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      if (this.policy.required) findings.push({ reason: XDO_REASON.MISSING })
      return { safe: !this.policy.required, noopen: false, findings }
    }
    const raw = String(headerValue)
    const value = raw.trim()
    if (value === '') {
      findings.push({ reason: XDO_REASON.EMPTY })
      return { safe: false, noopen: false, findings }
    }
    if (this.policy.rejectControlChars && xdoHasControlChar(raw)) {
      findings.push({ reason: XDO_REASON.CONTROL_CHAR })
    }
    if (value.indexOf(',') >= 0) {
      findings.push({ reason: XDO_REASON.MULTIPLE })
    }
    const ok = value.split(',')[0].trim().toLowerCase() === XDO_NOOPEN
    if (!ok) {
      findings.push({ reason: XDO_REASON.NOT_NOOPEN, value: value })
    }
    return { safe: findings.length === 0, noopen: ok, findings }
  }
}

module.exports = Object.freeze({
  XDO_HEADER: XDO_HEADER,
  XDO_NOOPEN: XDO_NOOPEN,
  XDO_REASON: XDO_REASON,
  defaultXdoPolicy: defaultXdoPolicy,
  XDownloadOptionsGuard: XDownloadOptionsGuard
})
