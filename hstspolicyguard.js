'use strict'

// hstspolicyguard.js —— HTTP Strict-Transport-Security（HSTS）响应头守卫。
//
// 威胁模型：
//   HSTS 告诉浏览器"本域在一段时间内只许用 HTTPS 访问"，是抗 SSL 剥离 / 首跳降级的核心防线。
//   配置失误会直接让防护失效或留下可利用窗口：
//     - max-age 太小（甚至 0）：几乎不提供保护，0 表示主动撤销；
//     - 在明文 HTTP 响应里设置 HSTS：按规范浏览器必须忽略，给站点造成"已防护"的错觉；
//     - 含多个 max-age / 重复指令：解析歧义，不同实现取首个或末个，攻击者可借注入头压掉真值；
//     - preload 域却没有 includeSubDomains：进预加载列表的资格不全，子域仍可被降级；
//     - 指令里夹带控制字符 / 非法空白：可能被下游代理拆分或走私。
//
// 本模块只做纯字符串解析（无正则依赖），把一条 HSTS 头值评估为结构化结论，
// 并给出推荐基线值；由网络层在收到响应头时调用。

const HSTS_HEADER = 'strict-transport-security'

const HSTS_REASON = Object.freeze({
  MISSING: 'hsts-missing',
  EMPTY: 'hsts-empty',
  INSECURE_TRANSPORT: 'hsts-set-over-http',
  MAX_AGE_MISSING: 'hsts-max-age-missing',
  MAX_AGE_ZERO: 'hsts-max-age-zero',
  MAX_AGE_TOO_SHORT: 'hsts-max-age-too-short',
  DUPLICATE_MAX_AGE: 'hsts-duplicate-max-age',
  DUPLICATE_DIRECTIVE: 'hsts-duplicate-directive',
  BAD_MAX_AGE: 'hsts-bad-max-age',
  PRELOAD_WITHOUT_SUBDOMAINS: 'hsts-preload-without-includesubdomains',
  CONTROL_CHAR: 'hsts-control-char',
  UNKNOWN_DIRECTIVE: 'hsts-unknown-directive'
})

// 进入预加载列表普遍要求的基线（各家浏览器实际门槛，取常用值）。
const HSTS_PRELOAD_MIN_MAX_AGE = 31536000 // 1 年（秒）
const HSTS_SAFE_MIN_MAX_AGE = 31536000 // 常规安全基线也按 1 年

// 允许的布尔型指令（无值）。
const HSTS_FLAGS = Object.freeze({
  includesubdomains: true,
  preload: true
})

function defaultHstsPolicy () {
  return {
    minMaxAge: HSTS_SAFE_MIN_MAX_AGE,
    preloadMinMaxAge: HSTS_PRELOAD_MIN_MAX_AGE,
    requireIncludeSubDomainsForPreload: true,
    rejectUnknownDirective: false, // 前向兼容：默认只提示不拒绝
    rejectControlChars: true
  }
}

function hstsHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

// 解析形如 "max-age=31536000; includeSubDomains; preload" 的头值。
// 返回 { directives:[{name,raw,value}], maxAge:number|null, maxAgeCount, flags:Set-like object,
//        duplicates:{name:count}, malformed:[token] }
function parseHsts (value) {
  const result = {
    maxAge: null,
    maxAgeCount: 0,
    flags: {},
    directives: [],
    duplicates: {},
    malformed: []
  }
  const seen = {}
  const parts = value.split(';')
  for (let i = 0; i < parts.length; i++) {
    const raw = parts[i]
    const token = raw.trim()
    if (token === '') {
      // 允许空段（结尾分号），不算畸形。
      continue
    }
    let name = token
    let val = null
    const eq = token.indexOf('=')
    if (eq >= 0) {
      name = token.slice(0, eq).trim()
      val = token.slice(eq + 1).trim()
    }
    const lower = name.toLowerCase()
    if (lower === '') {
      result.malformed.push(token)
      continue
    }
    result.directives.push({ name: lower, value: val, raw: token })
    if (seen[lower] !== undefined) {
      result.duplicates[lower] = (result.duplicates[lower] || 1) + 1
    }
    seen[lower] = true

    if (lower === 'max-age') {
      result.maxAgeCount++
      if (val !== null && val !== '' && hstsIsInteger(val)) {
        result.maxAge = parseInt(val, 10)
      } else {
        result.malformed.push(token)
      }
    } else if (HSTS_FLAGS[lower]) {
      result.flags[lower] = true
    }
  }
  return result
}

function hstsIsInteger (s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return true
}

class HstsPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultHstsPolicy(), policy || {})
  }

  // headerValue：HSTS 头值字符串（可为 null/undefined，表示缺失）。
  // context：{ isSecureTransport:boolean }，标识响应是否来自 HTTPS。
  evaluate (headerValue, context) {
    const pol = this.policy
    const ctx = context || {}
    const findings = []

    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: HSTS_REASON.MISSING })
      return { safe: false, findings, directives: [] }
    }
    const value = String(headerValue)
    if (value.trim() === '') {
      findings.push({ reason: HSTS_REASON.EMPTY })
      return { safe: false, findings, directives: [] }
    }
    if (pol.rejectControlChars && hstsHasControlChar(value)) {
      findings.push({ reason: HSTS_REASON.CONTROL_CHAR })
    }

    const parsed = parseHsts(value)

    if (ctx.isSecureTransport === false) {
      findings.push({ reason: HSTS_REASON.INSECURE_TRANSPORT })
    }
    if (parsed.maxAgeCount >= 2) {
      findings.push({ reason: HSTS_REASON.DUPLICATE_MAX_AGE, count: parsed.maxAgeCount })
    }
    Object.keys(parsed.duplicates).forEach(function (name) {
      if (name !== 'max-age') {
        findings.push({ reason: HSTS_REASON.DUPLICATE_DIRECTIVE, directive: name })
      }
    })
    if (parsed.maxAgeCount === 0) {
      findings.push({ reason: HSTS_REASON.MAX_AGE_MISSING })
    } else if (parsed.maxAge === null) {
      findings.push({ reason: HSTS_REASON.BAD_MAX_AGE })
    } else if (parsed.maxAge === 0) {
      findings.push({ reason: HSTS_REASON.MAX_AGE_ZERO })
    } else if (parsed.maxAge < pol.minMaxAge) {
      findings.push({ reason: HSTS_REASON.MAX_AGE_TOO_SHORT, maxAge: parsed.maxAge })
    }

    if (parsed.flags.preload && pol.requireIncludeSubDomainsForPreload &&
        !parsed.flags.includesubdomains) {
      findings.push({ reason: HSTS_REASON.PRELOAD_WITHOUT_SUBDOMAINS })
    }

    if (pol.rejectUnknownDirective) {
      parsed.directives.forEach(function (d) {
        if (d.name !== 'max-age' && !HSTS_FLAGS[d.name]) {
          findings.push({ reason: HSTS_REASON.UNKNOWN_DIRECTIVE, directive: d.name })
        }
      })
    }

    return {
      safe: findings.length === 0,
      findings: findings,
      directives: parsed.directives,
      maxAge: parsed.maxAge,
      flags: parsed.flags
    }
  }

  // 便于从一组响应头中取值（header 名大小写不敏感）。
  evaluateHeaders (headers, context) {
    const map = headers || {}
    let v = null
    const names = Object.keys(map)
    for (let i = 0; i < names.length; i++) {
      if (names[i].toLowerCase() === HSTS_HEADER) {
        v = map[names[i]]
        break
      }
    }
    return this.evaluate(v, context)
  }
}

module.exports = Object.freeze({
  HSTS_HEADER: HSTS_HEADER,
  HSTS_REASON: HSTS_REASON,
  HSTS_SAFE_MIN_MAX_AGE: HSTS_SAFE_MIN_MAX_AGE,
  HSTS_PRELOAD_MIN_MAX_AGE: HSTS_PRELOAD_MIN_MAX_AGE,
  defaultHstsPolicy: defaultHstsPolicy,
  parseHsts: parseHsts,
  HstsPolicyGuard: HstsPolicyGuard
})
