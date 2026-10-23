'use strict'

// contentsecuritypolicyguard.js —— Content-Security-Policy 结构化解析与加固守卫。
//
// 威胁模型：
//   CSP 是抗 XSS / 数据外泄 / 点击劫持的主防线。一张写错的 CSP 等于没有：
//     - script-src 含 'unsafe-inline'/'unsafe-eval'、通配 *、data:、http: 源：脚本注入仍可执行；
//     - 没有 script-src 且 default-src 也缺失：脚本完全不受限；
//     - object-src 不限制：老旧插件路径可执行活动内容；
//     - base-uri 缺失：注入 <base> 可把相对脚本地址重定向到攻击者域；
//     - frame-ancestors 缺失：可被任意站点嵌套（点击劫持）；
//     - 同一指令重复出现：浏览器只认第一条，第二条形同虚设（常见的"以为加了其实没加"）；
//     - 'strict-dynamic' 同时给 host 源/'unsafe-inline'：这些源被忽略，给人虚假安全感；
//     - form-action 缺失：表单可被提交到任意外部域（数据外泄）。
//
// 本模块无正则，按 ';' 切指令、按空白切 source token，给出逐条 finding 与收紧建议。

const CSP_HEADER = 'content-security-policy'

const CSP_REASON = Object.freeze({
  MISSING: 'csp-missing',
  EMPTY: 'csp-empty',
  DUPLICATE_DIRECTIVE: 'csp-duplicate-directive',
  SCRIPT_SRC_MISSING: 'csp-script-src-missing',
  UNSAFE_INLINE: 'csp-unsafe-inline',
  UNSAFE_EVAL: 'csp-unsafe-eval',
  WILDCARD_SOURCE: 'csp-wildcard-source',
  SCHEME_SOURCE: 'csp-dangerous-scheme-source',
  DATA_OR_BLOB_SCRIPT: 'csp-data-blob-script-source',
  OBJECT_SRC_UNRESTRICTED: 'csp-object-src-unrestricted',
  BASE_URI_MISSING: 'csp-base-uri-missing',
  FRAME_ANCESTORS_MISSING: 'csp-frame-ancestors-missing',
  FORM_ACTION_MISSING: 'csp-form-action-missing',
  STRICT_DYNAMIC_CONFLICT: 'csp-strict-dynamic-conflict',
  NONCE_WITH_UNSAFE_INLINE: 'csp-nonce-with-unsafe-inline',
  UPGRADE_INSECURE_MISSING: 'csp-upgrade-insecure-requests-missing',
  UNKNOWN_DIRECTIVE: 'csp-unknown-directive',
  CONTROL_CHAR: 'csp-control-char'
})

// 已知指令集合（CSP3 常用面）。
const CSP_DIRECTIVES = Object.freeze({
  'default-src': 1, 'script-src': 1, 'script-src-elem': 1, 'script-src-attr': 1,
  'style-src': 1, 'style-src-elem': 1, 'style-src-attr': 1, 'img-src': 1,
  'font-src': 1, 'connect-src': 1, 'media-src': 1, 'object-src': 1,
  'child-src': 1, 'frame-src': 1, 'worker-src': 1, 'manifest-src': 1,
  'prefetch-src': 1, 'base-uri': 1, 'form-action': 1, 'frame-ancestors': 1,
  'navigate-to': 1, 'sandbox': 1, 'report-uri': 1, 'report-to': 1,
  'upgrade-insecure-requests': 1, 'block-all-mixed-content': 1,
  'require-trusted-types-for': 1, 'trusted-types': 1, 'require-sri-for': 1
})

// 取值为 source-list 的指令（其余如 frame-ancestors/base-uri 也是 source-list 语义）。
const CSP_SOURCE_LIST = Object.freeze({
  'default-src': 1, 'script-src': 1, 'style-src': 1, 'img-src': 1, 'font-src': 1,
  'connect-src': 1, 'media-src': 1, 'object-src': 1, 'child-src': 1, 'frame-src': 1,
  'worker-src': 1, 'manifest-src': 1, 'base-uri': 1, 'form-action': 1,
  'frame-ancestors': 1, 'script-src-elem': 1
})

function defaultCspPolicy () {
  return {
    requireObjectSrcNone: true,
    requireBaseUri: true,
    requireFrameAncestors: true,
    requireFormAction: true,
    recommendUpgradeInsecure: true,
    rejectControlChars: true,
    rejectUnknownDirective: false
  }
}

function cspHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

function cspTokens (segment) {
  const out = []
  let cur = ''
  for (let i = 0; i < segment.length; i++) {
    const c = segment.charAt(i)
    if (c === ' ' || c === '\t') {
      if (cur !== '') { out.push(cur); cur = '' }
    } else {
      cur += c
    }
  }
  if (cur !== '') out.push(cur)
  return out
}

// 解析整条 CSP，返回 { directives:[{name,tokens,raw}], byName:{}, duplicates:[name] }
// 重复指令保留所有，但 byName 指向第一条（与浏览器一致）。
function parseCsp (value) {
  const directives = []
  const byName = {}
  const duplicates = []
  const parts = String(value).split(';')
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i].trim()
    if (seg === '') continue
    const toks = cspTokens(seg)
    if (toks.length === 0) continue
    const name = toks[0].toLowerCase()
    const dir = { name: name, tokens: toks.slice(1), raw: seg }
    directives.push(dir)
    if (Object.prototype.hasOwnProperty.call(byName, name)) {
      duplicates.push(name)
    } else {
      byName[name] = dir
    }
  }
  return { directives: directives, byName: byName, duplicates: duplicates }
}

function cspSourceKind (tok) {
  const t = tok.toLowerCase()
  if (t === "'unsafe-inline'") return 'unsafe-inline'
  if (t === "'unsafe-eval'" || t === "'unsafe-hashes'") return 'unsafe-evalish'
  if (t === '*') return 'wildcard'
  if (t === 'http:') return 'scheme-http'
  if (t === 'https:') return 'scheme-https'
  if (t === 'data:' || t === 'blob:' || t === 'filesystem:') return 'data-blob-scheme'
  if (t.charAt(t.length - 1) === ':' && t !== 'wss:') {
    return 'scheme'
  }
  return 'host-or-keyword'
}

// 解析某个 source-list 指令的有效来源类别。
function cspClassifySources (dir) {
  const kinds = { wildcard: false, httpScheme: false, dataBlob: false, unsafeInline: false,
    unsafeEval: false, strictDynamic: false, nonce: false, hash: false, self: false, none: false }
  if (!dir) return kinds
  dir.tokens.forEach((tok) => {
    const t = tok.toLowerCase()
    if (t === '*') kinds.wildcard = true
    if (t === 'http:') kinds.httpScheme = true
    if (t === 'data:' || t === 'blob:') kinds.dataBlob = true
    if (t === "'unsafe-inline'") kinds.unsafeInline = true
    if (t === "'unsafe-eval'" || t === "'unsafe-hashes'") kinds.unsafeEval = true
    if (t === "'strict-dynamic'") kinds.strictDynamic = true
    if (t.indexOf("'nonce-") === 0) kinds.nonce = true
    if (t.indexOf("'sha256-") === 0 || t.indexOf("'sha384-") === 0 || t.indexOf("'sha512-") === 0) {
      kinds.hash = true
    }
    if (t === "'self'") kinds.self = true
    if (t === "'none'") kinds.none = true
  })
  return kinds
}

class ContentSecurityPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCspPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: CSP_REASON.MISSING })
      return { safe: false, findings, byName: {} }
    }
    const raw = String(headerValue)
    if (raw.trim() === '') {
      findings.push({ reason: CSP_REASON.EMPTY })
      return { safe: false, findings, byName: {} }
    }
    if (pol.rejectControlChars && cspHasControlChar(raw)) {
      findings.push({ reason: CSP_REASON.CONTROL_CHAR })
    }

    const parsed = parseCsp(raw)
    parsed.duplicates.forEach((name) => {
      findings.push({ reason: CSP_REASON.DUPLICATE_DIRECTIVE, directive: name })
    })
    if (pol.rejectUnknownDirective) {
      parsed.directives.forEach((d) => {
        if (!CSP_DIRECTIVES[d.name]) {
          findings.push({ reason: CSP_REASON.UNKNOWN_DIRECTIVE, directive: d.name })
        }
      })
    }

    const script = parsed.byName['script-src'] || parsed.byName['script-src-elem']
    const fallback = parsed.byName['default-src']
    const effective = script || fallback
    if (!effective) {
      findings.push({ reason: CSP_REASON.SCRIPT_SRC_MISSING })
    } else {
      const k = cspClassifySources(effective)
      if (k.unsafeInline) {
        findings.push({ reason: CSP_REASON.UNSAFE_INLINE, directive: effective.name })
      }
      if (k.unsafeEval) {
        findings.push({ reason: CSP_REASON.UNSAFE_EVAL, directive: effective.name })
      }
      if (k.wildcard) {
        findings.push({ reason: CSP_REASON.WILDCARD_SOURCE, directive: effective.name })
      }
      if (k.httpScheme || k.dataBlob) {
        findings.push({
          reason: k.dataBlob ? CSP_REASON.DATA_OR_BLOB_SCRIPT : CSP_REASON.SCHEME_SOURCE,
          directive: effective.name
        })
      }
      if (k.nonce && k.unsafeInline) {
        findings.push({ reason: CSP_REASON.NONCE_WITH_UNSAFE_INLINE, directive: effective.name })
      }
      if (k.strictDynamic && !k.nonce && !k.hash) {
        findings.push({ reason: CSP_REASON.STRICT_DYNAMIC_CONFLICT, detail: 'strict-dynamic-without-nonce-or-hash' })
      }
    }

    // object-src：缺失则回退 default-src；两者都没有 = 插件对象不受限。
    const objectDir = parsed.byName['object-src'] || fallback
    const objectK = cspClassifySources(objectDir)
    if (pol.requireObjectSrcNone && (!objectDir || (!objectK.none && (objectK.wildcard || objectDir.tokens.length === 0)))) {
      findings.push({ reason: CSP_REASON.OBJECT_SRC_UNRESTRICTED })
    }

    if (pol.requireBaseUri && !parsed.byName['base-uri']) {
      findings.push({ reason: CSP_REASON.BASE_URI_MISSING })
    }
    if (pol.requireFrameAncestors && !parsed.byName['frame-ancestors']) {
      findings.push({ reason: CSP_REASON.FRAME_ANCESTORS_MISSING })
    }
    if (pol.requireFormAction && !parsed.byName['form-action']) {
      findings.push({ reason: CSP_REASON.FORM_ACTION_MISSING })
    }
    if (pol.recommendUpgradeInsecure && !parsed.byName['upgrade-insecure-requests']) {
      findings.push({ reason: CSP_REASON.UPGRADE_INSECURE_MISSING })
    }

    return {
      safe: findings.length === 0,
      findings: findings,
      directives: parsed.directives,
      byName: parsed.byName,
      duplicates: parsed.duplicates
    }
  }
}

module.exports = Object.freeze({
  CSP_HEADER: CSP_HEADER,
  CSP_REASON: CSP_REASON,
  CSP_DIRECTIVES: CSP_DIRECTIVES,
  CSP_SOURCE_LIST: CSP_SOURCE_LIST,
  defaultCspPolicy: defaultCspPolicy,
  parseCsp: parseCsp,
  cspClassifySources: cspClassifySources,
  cspSourceKind: cspSourceKind,
  ContentSecurityPolicyGuard: ContentSecurityPolicyGuard
})
