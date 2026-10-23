'use strict'

// requestsmugglingguard.js —— HTTP 请求走私（Request Smuggling）的 CL.TE / TE.CL 头组合守卫。
//
// 威胁模型：
//   浏览器主进程、内置代理或调试通道若转发"同时带 Content-Length 与 Transfer-Encoding"的请求，
//   前端代理与后端对这两个头的取舍不一致，攻击者可把一个请求"偷渡"成下一个排队请求的前缀，
//   劫持其他用户请求、绕过鉴权（HTTP Request Smuggling）。
//   本模块审计出向请求头集合：
//     - CL 与 TE 同时出现（歧义，拒绝或规范化）；
//     - 多个 Content-Length（必须拒绝）；
//     - Transfer-Encoding 不是合法 token 列表（如 "chunked, identity" 之外的值、混淆写法）；
//     - Content-Length 非数字/负数。
//   纯字符处理，不使用正则。

const SM_REASON = Object.freeze({
  CL_TE_BOTH: 'request-has-both-content-length-and-transfer-encoding',
  MULTIPLE_CL: 'request-has-multiple-content-length-headers',
  BAD_CL: 'content-length-malformed',
  BAD_TE: 'transfer-encoding-unsupported-token',
  TE_OBSFUSCATED: 'transfer-encoding-obfuscated-value'
})

const SM_ALLOWED_TE = ['chunked', 'identity']

function smTrim (s) {
  let a = 0
  let b = s.length
  while (a < b && (s[a] === ' ' || s[a] === '\t')) a++
  while (b > a && (s[b - 1] === ' ' || s[b - 1] === '\t')) b--
  return s.slice(a, b)
}

function smLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function smIsDigits (s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return true
}

// 走私常用混淆：CR/LF/NUL、制表位、连续空格、非 ASCII 字节、空 token。
function smObfuscated (s) {
  if (s.indexOf('  ') >= 0) return true
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 9 || c === 13 || c === 10 || c === 0) return true
    if (c > 0x7E) return true
  }
  return false
}

// headers: [{ name, value }]（name 大小写不敏感）
function auditRequestHeaders (headers) {
  const findings = []
  const cl = []
  const te = []
  for (const h of headers) {
    const n = smLower(smTrim(h.name))
    if (n === 'content-length') cl.push(smTrim(h.value))
    // TE 保留原始值：尾部制表位/CRLF 等混淆若被 trim 掉就检测不到了。
    if (n === 'transfer-encoding') te.push(String(h.value))
  }
  if (cl.length > 1) findings.push({ reason: SM_REASON.MULTIPLE_CL })
  for (const v of cl) {
    if (!smIsDigits(v)) findings.push({ reason: SM_REASON.BAD_CL, detail: v })
  }
  if (te.length > 0) {
    for (const v of te) {
      if (smObfuscated(v)) {
        findings.push({ reason: SM_REASON.TE_OBSFUSCATED, detail: v })
      }
      const tokens = smLower(v).split(',').map(smTrim)
      for (const tk of tokens) {
        if (SM_ALLOWED_TE.indexOf(tk) < 0) {
          findings.push({ reason: SM_REASON.BAD_TE, detail: tk })
        }
      }
    }
  }
  if (cl.length > 0 && te.length > 0) findings.push({ reason: SM_REASON.CL_TE_BOTH })
  return { safe: findings.length === 0, findings: findings }
}

class RequestSmugglingGuard {
  audit (headers) {
    return auditRequestHeaders(headers || [])
  }
}

module.exports = Object.freeze({
  SM_REASON: SM_REASON,
  auditRequestHeaders: auditRequestHeaders,
  RequestSmugglingGuard: RequestSmugglingGuard
})
