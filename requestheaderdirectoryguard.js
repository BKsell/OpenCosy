'use strict'

// requestheaderdirectoryguard.js —— HTTP 请求头安全分级目录。
//
// 威胁模型：
//   凭据/寻址/逐跳请求头需受控或禁止远端注入，协商/条件请求头常规。纯字符查表，不用正则。

const QHD_REASON = Object.freeze({
  BLOCK: 'requestheaderdirectory-input-hits-blocked-catalog',
  WARN: 'requestheaderdirectory-input-hits-review-catalog',
  PREFIX: 'requestheaderdirectory-input-hits-dangerous-prefix',
  EMPTY: 'requestheaderdirectory-input-is-empty'
})

const QHD_BLOCK = Object.freeze([
  'Proxy-Authorization',
  'X-Forwarded-Host',
  'X-Forwarded-For',
  'X-Forwarded-Proto',
  'X-Forwarded-Scheme',
  'X-Real-Ip',
  'X-Original-URL',
  'X-Rewrite-URL',
  'X-HTTP-Method-Override',
  'X-HTTP-Method',
  'X-Method-Override',
  'Forwarded',
  'Via',
  'X-Host',
  'X-Forwarded-Server',
  'X-Forwarded-Port',
  'X-Custom-IP-Authorization',
  'X-Cluster-Client-Ip',
  'True-Client-Ip',
  'CF-Connecting-IP',
  'Fastly-Client-Ip',
  'X-Envoy-External-Address',
  'X-Amzn-Trace-Id',
  'Connection',
  'Proxy-Connection',
  'Keep-Alive',
  'Transfer-Encoding',
  'TE',
  'Trailer',
  'Upgrade',
])

const QHD_WARN = Object.freeze([
  'Host',
  'Authorization',
  'Cookie',
  'Cookie2',
  'X-Api-Key',
  'X-Auth-Token',
  'X-Access-Token',
  'X-Csrf-Token',
  'X-Xsrf-Token',
  'X-Session-Id',
  'X-Session-Token',
  'X-Request-Id',
  'X-Correlation-Id',
  'X-Trace-Id',
  'Referer',
  'Origin',
  'Content-Length',
  'Content-Range',
  'Range',
  'If-Range',
  'From',
  'Expect',
  'Destination',
  'X-Client-Cert',
  'X-SSL-Client-Cert',
  'X-Remote-User',
  'X-Forwarded-User',
  'X-User-Id',
  'X-Identity',
  'X-Email',
  'X-Username',
  'Proxy-Authenticate',
  'WWW-Authenticate',
  'Accept',
  'Accept-Charset',
  'Accept-Encoding',
  'Accept-Language',
  'Accept-Datetime',
  'Accept-Patch',
  'Accept-Post',
  'Content-Type',
  'Content-Language',
  'Content-Encoding',
  'Content-Location',
  'Content-Disposition',
  'Cache-Control',
  'Pragma',
  'If-Match',
  'If-None-Match',
  'If-Modified-Since',
  'If-Unmodified-Since',
])

const QHD_ALLOW = Object.freeze([
  'DNT',
  'Sec-Gpc',
  'Sec-Ch-Ua',
  'Sec-Ch-Ua-Mobile',
  'Sec-Ch-Ua-Platform',
  'Sec-Fetch-Site',
  'Sec-Fetch-Mode',
  'Sec-Fetch-User',
  'Sec-Fetch-Dest',
  'Save-Data',
  'Device-Memory',
  'Downlink',
  'Ect',
  'Rtt',
  'Viewport-Width',
  'Width',
  'Priority',
  'Service-Worker-Navigation-Preload',
  'User-Agent',
  'Accept-Ranges',
  'Date',
  'Age',
  'Max-Forwards',
])

const QHD_PREFIX_LIT = Object.freeze([
])
const QHD_PREFIX_REASON = Object.freeze([
])

function QHDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function QHDIn (list, v) {
  for (const x of list) { if (QHDLower(x) === v) return true }
  return false
}

function QHDSplit (inStr) {
  return inStr.split(',')
}

class QHDGuard {
  static get blockList () { return QHD_BLOCK }
  static get warnList () { return QHD_WARN }
  static get allowList () { return QHD_ALLOW }
  static get prefixLit () { return QHD_PREFIX_LIT }
  audit (inStr) {
    const findings = []
    if (typeof inStr !== 'string' || inStr.length === 0) return { safe: false, findings: [{ reason: QHD_REASON.EMPTY }] }
    for (const tok of QHDSplit(inStr)) {
      const cmp = QHDLower(String(tok).trim())
      if (QHDIn(QHD_BLOCK, cmp)) findings.push({ reason: QHD_REASON.BLOCK, detail: cmp })
      else if (QHDIn(QHD_WARN, cmp)) findings.push({ reason: QHD_REASON.WARN, detail: cmp })
      for (let i = 0; i < QHD_PREFIX_LIT.length; i++) {
        const lit = QHD_PREFIX_LIT[i]
        if (cmp.length >= lit.length && cmp.slice(0, lit.length) === lit) findings.push({ reason: QHD_REASON.PREFIX, detail: QHD_PREFIX_REASON[i] })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  QHD_REASON: QHD_REASON,
  QHD_BLOCK: QHD_BLOCK,
  QHD_WARN: QHD_WARN,
  QHD_ALLOW: QHD_ALLOW,
  QHDGuard: QHDGuard
})
