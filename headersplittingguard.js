'use strict'

// headersplittingguard.js —— 出站/入站 HTTP 头值的响应拆分（CRLF Injection）守卫。
//
// 威胁模型：
//   下载文件名、自定义头（x-*）、重定向 Location 等若由页面/远端值拼装且未过滤 CR LF，攻击者可注入
//   "\r\nSet-Cookie: ..." 直接多写一个响应头（HTTP Response Splitting），或注入空行伪造响应体，
//   在老旧代理/缓存上造成缓存投毒与会话固定。NUL 同样能截断部分原生头处理。
//   本模块：审计单个头名/头值是否含 CR、LF、NUL，并提供 sanitizeHeaderValue。
//   纯字符处理，不使用正则。

const HS_REASON = Object.freeze({
  CRLF_IN_VALUE: 'http-header-value-contains-crlf',
  NUL_IN_VALUE: 'http-header-value-contains-nul',
  BAD_HEADER_NAME: 'http-header-name-illegal',
  NON_STRING: 'http-header-value-not-string'
})

function hsHasControl (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 13 || c === 10) return 'crlf'
    if (c === 0) return 'nul'
  }
  return null
}

function hsValidName (name) {
  // token：可见 ASCII，排除分隔符与空格
  const bad = '()<>@,;:\\"/[]?={} \t'
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i)
    if (c <= 0x20 || c >= 0x7F) return false
    if (bad.indexOf(name[i]) >= 0) return false
  }
  return name.length > 0
}

function auditHeader (name, value) {
  const findings = []
  if (!hsValidName(String(name))) findings.push({ reason: HS_REASON.BAD_HEADER_NAME, detail: String(name) })
  if (typeof value !== 'string') {
    findings.push({ reason: HS_REASON.NON_STRING })
    return { safe: false, findings: findings }
  }
  const hit = hsHasControl(value)
  if (hit === 'crlf') findings.push({ reason: HS_REASON.CRLF_IN_VALUE })
  if (hit === 'nul') findings.push({ reason: HS_REASON.NUL_IN_VALUE })
  return { safe: findings.length === 0, findings: findings }
}

// 删除 CR/LF/NUL 及其后内容风险，统一替换为空格并折叠连续空白，再裁剪首尾空白。
function sanitizeHeaderValue (value) {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    if (c === 13 || c === 10 || c === 0) {
      if (out.length > 0 && out[out.length - 1] !== ' ') out += ' '
      continue
    }
    out += value[i]
  }
  let start = 0
  let end = out.length
  while (start < end && (out[start] === ' ' || out[start] === '\t')) start++
  while (end > start && (out[end - 1] === ' ' || out[end - 1] === '\t')) end--
  return out.slice(start, end)
}

class HeaderSplittingGuard {
  audit (name, value) {
    return auditHeader(name, value)
  }

  sanitize (value) {
    return sanitizeHeaderValue(String(value))
  }
}

module.exports = Object.freeze({
  HS_REASON: HS_REASON,
  hsValidName: hsValidName,
  sanitizeHeaderValue: sanitizeHeaderValue,
  HeaderSplittingGuard: HeaderSplittingGuard
})
