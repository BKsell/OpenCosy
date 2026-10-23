'use strict'

// cachecontrolguard.js —— Cache-Control 敏感响应缓存策略守卫。
//
// 威胁模型：
//   登录后的账户页、含会话 token / 个人数据的 JSON / API 响应若被允许缓存，会残留在：
//   浏览器后退缓存、共享代理缓存、同一台机器的其他用户账户或 kiosk 环境，导致凭据与隐私泄露。
// 危险写法（在敏感响应上）：
//   - 没有 no-store / no-cache：默认启发式缓存可能生效；
//   - public：显式允许共享缓存保存（即使有 Authorization 也会缓存）；
//   - max-age=<正数> / s-maxage=<正数> / immutable：在客户端或共享缓存中长期留存；
//   - 互相矛盾的指令（同时 no-store 与 max-age）：不同实现取舍不一；
//   - 形如 max-age 后被第二个 Cache-Control 头覆盖：重复指令解析歧义。
//
// 本模块解析逗号分隔的缓存指令集；由调用方通过 context.sensitive 标明是否为敏感响应。
// 非敏感响应不做强判，避免对静态资源误报。

const CC_HEADER = 'cache-control'
const CC_DIRECTIVE_NOSTORE = 'no-store'

const CC_REASON = Object.freeze({
  MISSING: 'cc-missing-on-sensitive',
  EMPTY: 'cc-empty',
  NO_STORE_MISSING: 'cc-sensitive-without-no-store',
  PUBLIC_ON_SENSITIVE: 'cc-public-on-sensitive',
  MAX_AGE_ON_SENSITIVE: 'cc-positive-max-age-on-sensitive',
  S_MAXAGE_ON_SENSITIVE: 'cc-positive-s-maxage-on-sensitive',
  IMMUTABLE_ON_SENSITIVE: 'cc-immutable-on-sensitive',
  CONTRADICTORY: 'cc-contradictory-directives',
  BAD_MAX_AGE: 'cc-bad-max-age',
  DUPLICATE_DIRECTIVE: 'cc-duplicate-directive',
  CONTROL_CHAR: 'cc-control-char'
})

function defaultCacheControlPolicy () {
  return {
    rejectControlChars: true,
    // 非敏感响应默认只解析不强判；调用方可打开 enforceMaxAgeCeiling 做上限检查。
    enforceMaxAgeCeiling: false,
    maxAgeCeiling: 0
  }
}

function ccHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

function ccIsDigits (s) {
  if (s.length === 0) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return true
}

// 返回 { flags:Set-like, values:{name:rawNumber|null}, order:[name], duplicates:[name], bad:[name] }
function parseCacheControl (value) {
  const flags = {}
  const values = {}
  const order = []
  const duplicates = []
  const bad = []
  const parts = String(value).split(',')
  for (let i = 0; i < parts.length; i++) {
    const tok = parts[i].trim()
    if (tok === '') continue
    let name = tok.toLowerCase()
    let val = null
    const eq = tok.indexOf('=')
    if (eq >= 0) {
      name = tok.slice(0, eq).trim().toLowerCase()
      val = tok.slice(eq + 1).trim()
    }
    if (name === '') continue
    if (flags[name] === true || Object.prototype.hasOwnProperty.call(values, name)) {
      duplicates.push(name)
    }
    order.push(name)
    if (val === null) {
      flags[name] = true
    } else {
      if (ccIsDigits(val)) {
        values[name] = parseInt(val, 10)
      } else {
        values[name] = null
        bad.push(name)
      }
    }
  }
  return { flags: flags, values: values, order: order, duplicates: duplicates, bad: bad }
}

class CacheControlGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCacheControlPolicy(), policy || {})
  }

  evaluate (headerValue, context) {
    const pol = this.policy
    const sensitive = !!(context && context.sensitive)
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      if (sensitive) findings.push({ reason: CC_REASON.MISSING })
      return { safe: !sensitive, sensitive: sensitive, findings, parsed: null }
    }
    const raw = String(headerValue)
    if (raw.trim() === '') {
      if (sensitive) findings.push({ reason: CC_REASON.EMPTY })
      return { safe: !sensitive, sensitive: sensitive, findings, parsed: null }
    }
    if (pol.rejectControlChars && ccHasControlChar(raw)) {
      findings.push({ reason: CC_REASON.CONTROL_CHAR })
    }
    const parsed = parseCacheControl(raw)
    parsed.duplicates.forEach((n) => findings.push({ reason: CC_REASON.DUPLICATE_DIRECTIVE, directive: n }))
    parsed.bad.forEach((n) => findings.push({ reason: CC_REASON.BAD_MAX_AGE, directive: n }))

    if (sensitive) {
      const noStore = !!parsed.flags[CC_DIRECTIVE_NOSTORE]
      if (!noStore) {
        findings.push({ reason: CC_REASON.NO_STORE_MISSING })
      }
      if (parsed.flags['public']) {
        findings.push({ reason: CC_REASON.PUBLIC_ON_SENSITIVE })
      }
      const maxAge = parsed.values['max-age']
      if (typeof maxAge === 'number' && maxAge > 0) {
        findings.push({ reason: CC_REASON.MAX_AGE_ON_SENSITIVE, maxAge: maxAge })
      }
      const sMaxAge = parsed.values['s-maxage']
      if (typeof sMaxAge === 'number' && sMaxAge > 0) {
        findings.push({ reason: CC_REASON.S_MAXAGE_ON_SENSITIVE, sMaxage: sMaxAge })
      }
      if (parsed.flags['immutable']) {
        findings.push({ reason: CC_REASON.IMMUTABLE_ON_SENSITIVE })
      }
      if (noStore && (parsed.flags['immutable'] ||
          (typeof maxAge === 'number' && maxAge > 0))) {
        findings.push({ reason: CC_REASON.CONTRADICTORY })
      }
    } else if (pol.enforceMaxAgeCeiling) {
      const maxAge = parsed.values['max-age']
      if (typeof maxAge === 'number' && maxAge > pol.maxAgeCeiling) {
        findings.push({ reason: CC_REASON.MAX_AGE_ON_SENSITIVE, maxAge: maxAge })
      }
    }

    return {
      safe: findings.length === 0,
      sensitive: sensitive,
      findings: findings,
      parsed: parsed
    }
  }
}

module.exports = Object.freeze({
  CC_HEADER: CC_HEADER,
  CC_REASON: CC_REASON,
  defaultCacheControlPolicy: defaultCacheControlPolicy,
  parseCacheControl: parseCacheControl,
  CacheControlGuard: CacheControlGuard
})
