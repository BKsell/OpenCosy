'use strict'

// uricomponentguard.js —— 出向 URI 各组件的长度、端口与百分号编码合法性守卫。
//
// 威胁模型：
//   浏览器内核/主进程拼下载、登录、代理 URL，组件级缺陷会引发截断、绕过或解析器分歧：
//     - 超长 URL/host/query 被下游组件截断；
//     - 端口越界（0、>65535）、非数字端口、v4 host 内多个冒号；
//     - 空 host（http:///path）；
//     - 畸形 %XX（%zz、%2、结尾%）导致不同解析器理解不一致；
//     - userinfo 内嵌凭据（http://user:pass@host）。
//   纯字符解析，不使用正则。

const UC_REASON = Object.freeze({
  URL_OVERLONG: 'uri-total-length-exceeds-limit',
  HOST_OVERLONG: 'uri-host-label-or-name-too-long',
  PORT_INVALID: 'uri-port-out-of-range-or-malformed',
  EMPTY_HOST: 'uri-has-empty-host',
  BAD_PERCENT: 'uri-percent-encoding-malformed',
  USERINFO: 'uri-contains-userinfo-credentials',
  MULTIPLE_PORTS: 'uri-host-contains-multiple-port-colons-outside-ipv6'
})

const UC_MAX_URL = 8192
const UC_MAX_HOST = 253
const UC_MAX_LABEL = 63

function ucIsHex (c) {
  return (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70)
}

class UriComponentGuard {
  // in: { fullUrl, scheme, host(不含端口/方括号), port(''表示无), hasUserInfo }
  evaluate (input) {
    const findings = []
    const inp = input || {}
    if (inp.fullUrl && inp.fullUrl.length > UC_MAX_URL) {
      findings.push({ reason: UC_REASON.URL_OVERLONG, detail: String(inp.fullUrl.length) })
    }
    if (inp.hasUserInfo) findings.push({ reason: UC_REASON.USERINFO })
    if (!inp.host) {
      findings.push({ reason: UC_REASON.EMPTY_HOST })
    } else if (inp.host.indexOf(':') < 0) {
      if (inp.host.length > UC_MAX_HOST) findings.push({ reason: UC_REASON.HOST_OVERLONG })
      const labels = inp.host.split('.')
      for (const label of labels) {
        if (label.length > UC_MAX_LABEL) {
          findings.push({ reason: UC_REASON.HOST_OVERLONG, detail: 'label>' + UC_MAX_LABEL })
          break
        }
      }
    }
    if (inp.port) {
      if (!this.validPort(inp.port)) findings.push({ reason: UC_REASON.PORT_INVALID, detail: inp.port })
    }
    if (inp.host) {
      const colons = inp.host.split('').filter((c) => c === ':').length
      // IPv6 主机会有多个冒号；已剥离端口的 v4 主机位若残留恰好一个冒号即多端口/畸形
      if (colons === 1) findings.push({ reason: UC_REASON.MULTIPLE_PORTS })
    }
    if (inp.fullUrl) {
      for (let i = 0; i < inp.fullUrl.length; i++) {
        if (inp.fullUrl[i] === '%') {
          if (i + 2 >= inp.fullUrl.length ||
              !ucIsHex(inp.fullUrl.charCodeAt(i + 1)) ||
              !ucIsHex(inp.fullUrl.charCodeAt(i + 2))) {
            findings.push({ reason: UC_REASON.BAD_PERCENT, detail: String(i) })
          }
        }
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }

  validPort (p) {
    if (!p || p.length > 5) return false
    let n = 0
    for (let i = 0; i < p.length; i++) {
      const c = p.charCodeAt(i)
      if (c < 48 || c > 57) return false
      n = n * 10 + (c - 48)
      if (n > 65535) return false
    }
    return n > 0
  }
}

module.exports = Object.freeze({
  UC_REASON: UC_REASON,
  UC_MAX_URL: UC_MAX_URL,
  UriComponentGuard: UriComponentGuard
})
