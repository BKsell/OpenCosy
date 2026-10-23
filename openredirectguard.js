'use strict'

// openredirectguard.js —— 开放重定向守卫。
//
// 威胁模型：
//   登录/登出/回跳端点把用户可控参数直接拼进 Location（3xx），可被构造成钓鱼跳板：
//     https://app.test/login?next=https://evil.test  → 用户在可信域名上被跳到钓鱼站，
//   还会带着 Referer 泄露跳转令牌。绕过形态很多：
//     - 显式绝对 URL 到外域；
//     - 协议相对 "//evil.test"；
//     - 反斜杠混淆 "/\\evil.test"、"\\evil.test"；
//     - 无 scheme 的 "evil.test"（部分客户端补全）；
//     - "https:evil.test"、"https:///evil.test"、whitespace/制表符前缀；
//     - "@" 用户名段 "https://app.test@evil.test"（真实主机是 evil.test）；
//     - 仅允许 http/https，禁止 javascript:/data: 等。
//
// 本模块对"目标 URL + 允许的应用来源集合"给出 allow/deny。

const ORD_REASON = Object.freeze({
  EMPTY_TARGET: 'ord-empty-target',
  EXTERNAL_ABSOLUTE: 'ord-external-absolute-url',
  PROTOCOL_RELATIVE: 'ord-protocol-relative',
  BACKSLASH_HOST: 'ord-backslash-host-confusion',
  USERINFO_HOST: 'ord-userinfo-host-spoof',
  NON_HTTP_SCHEME: 'ord-non-http-scheme',
  CONTROL_OR_WHITESPACE: 'ord-control-or-whitespace',
  BARE_HOST: 'ord-bare-hostname'
})

function defaultOrdPolicy () {
  return {
    allowedOrigins: [],
    allowRelativePath: true,
    allowBareHostname: false,
    rejectControlChars: true
  }
}

function ordTrimControl (s) {
  let b = 0
  let e = s.length
  const isSpaceOrCtl = (ch) => {
    const c = ch.charCodeAt(0)
    return c <= 0x20 || c === 0x7F
  }
  while (b < e && isSpaceOrCtl(s.charAt(b))) b++
  while (e > b && isSpaceOrCtl(s.charAt(e - 1))) e--
  return s.slice(b, e)
}

function ordHasControl (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1F || c === 0x7F) return true
  }
  return false
}

// 归一化来源比较键。
function ordOriginKey (u) {
  const s = String(u || '').toLowerCase()
  const idx = s.indexOf('://')
  if (idx < 0) return s
  const rest = s.slice(idx + 3)
  const slash = rest.indexOf('/')
  const host = slash < 0 ? rest : rest.slice(0, slash)
  return s.slice(0, idx + 3) + host
}

class OpenRedirectGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultOrdPolicy(), policy || {})
    this.allow = {}
    ;(this.policy.allowedOrigins || []).forEach((o) => {
      this.allow[ordOriginKey(o)] = true
    })
  }

  evaluate (target) {
    const pol = this.policy
    const findings = []
    if (target === null || target === undefined || String(target) === '') {
      findings.push({ reason: ORD_REASON.EMPTY_TARGET })
      return { safe: false, findings }
    }
    const orig = String(target)
    if (pol.rejectControlChars && ordHasControl(orig)) {
      findings.push({ reason: ORD_REASON.CONTROL_OR_WHITESPACE })
    }
    const t = ordTrimControl(orig)

    if (t.charAt(0) === '/' && t.charAt(1) !== '/' && t.charAt(1) !== '\\') {
      // 正常站内绝对路径 /path
      return { safe: pol.allowRelativePath, kind: 'path-absolute', findings }
    }
    if (t.charAt(0) === '/' && (t.charAt(1) === '/' || t.charAt(1) === '\\')) {
      findings.push({ reason: ORD_REASON.PROTOCOL_RELATIVE })
      return { safe: false, findings }
    }
    if (t.charAt(0) === '\\') {
      findings.push({ reason: ORD_REASON.BACKSLASH_HOST })
      return { safe: false, findings }
    }

    const colon = t.indexOf(':')
    const firstSlash = t.indexOf('/')
    const hasScheme = colon > 0 && (firstSlash < 0 || colon < firstSlash)
    if (hasScheme) {
      const scheme = t.slice(0, colon).toLowerCase()
      const rest = t.slice(colon + 1)
      // https:evil.test（缺 //）也当作可疑外跳。
      if (scheme === 'http' || scheme === 'https') {
        let authority = rest
        if (authority.charAt(0) === '/' && authority.charAt(1) === '/') {
          authority = authority.slice(2)
        } else {
          findings.push({ reason: ORD_REASON.EXTERNAL_ABSOLUTE })
          return { safe: false, findings }
        }
        // @ 段：https://trusted@evil —— 主机是 evil。
        if (authority.indexOf('@') >= 0) {
          findings.push({ reason: ORD_REASON.USERINFO_HOST })
          return { safe: false, findings }
        }
        const slash2 = authority.indexOf('/')
        const hostPort = slash2 < 0 ? authority : authority.slice(0, slash2)
        const key = scheme + '://' + hostPort.toLowerCase()
        if (this.allow[key]) return { safe: true, kind: 'absolute-allowed', origin: key, findings }
        findings.push({ reason: ORD_REASON.EXTERNAL_ABSOLUTE, origin: key })
        return { safe: false, findings }
      }
      findings.push({ reason: ORD_REASON.NON_HTTP_SCHEME, scheme: scheme })
      return { safe: false, findings }
    }

    // 无 scheme 且不是 / 开头：可能是 "evil.test" 裸主机名或相对段。
    if (t.charAt(0) === '?') return { safe: pol.allowRelativePath, kind: 'query', findings }
    if (t.indexOf('.') >= 0 && t.indexOf('/') < 0) {
      // 形如 evil.test / evil.test:8080
      if (!pol.allowBareHostname) {
        findings.push({ reason: ORD_REASON.BARE_HOST })
        return { safe: false, findings }
      }
    }
    return { safe: pol.allowRelativePath, kind: 'relative', findings }
  }
}

module.exports = Object.freeze({
  ORD_REASON: ORD_REASON,
  defaultOrdPolicy: defaultOrdPolicy,
  ordOriginKey: ordOriginKey,
  OpenRedirectGuard: OpenRedirectGuard
})
