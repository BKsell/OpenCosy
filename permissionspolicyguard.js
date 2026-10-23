'use strict'

// permissionspolicyguard.js —— Permissions-Policy 响应头守卫。
//
// 威胁模型：
//   Permissions-Policy 决定哪些来源可用摄像头、麦克风、定位、支付、USB、剪贴板等强能力。
//   默认 Chromium 对多数特性是 allowlist=self（嵌入的跨源 iframe 默认不可用），一旦页面显式
//   写宽松策略，就会把能力下放给任意来源或所有 iframe。危险写法：
//     - feature=* 或 feature（无 allowlist）：任意来源可用；
//     - feature=(self "https://a" ...)：把第三方源加进强能力白名单；
//     - 敏感特性没有被显式禁用 ()：本页自身仍可调用（取决于是否需要"连顶层都禁用"）；
//     - 语法错误 / 括号不匹配 / 未闭合引号：该指令整段失效，退回默认，可能违背预期；
//     - unload / 第三方无关特性被放开。
//
// 本模块做无正则的结构化解析：先按逗号切特性（origin 用引号包裹且不含逗号），
// 再解析特性名与括号内 allowlist，对敏感特性评估是否过度授权。

const PP_HEADER = 'permissions-policy'

const PP_REASON = Object.freeze({
  MISSING: 'pp-missing',
  EMPTY: 'pp-empty',
  WILDCARD: 'pp-wildcard-allow',
  ALLOW_ALL_OMITTED: 'pp-allowlist-omitted',
  THIRD_PARTY_ORIGIN: 'pp-third-party-origin',
  SENSITIVE_NOT_DISABLED: 'pp-sensitive-not-denied',
  SYNTAX_ERROR: 'pp-syntax-error',
  UNKNOWN_FEATURE: 'pp-unknown-feature',
  CONTROL_CHAR: 'pp-control-char'
})

// 默认视为"强能力/敏感"的特性集合（需要显式收紧）。
const PP_SENSITIVE = Object.freeze({
  camera: true,
  microphone: true,
  geolocation: true,
  payment: true,
  usb: true,
  'hid': true,
  serial: true,
  bluetooth: true,
  midi: true,
  'clipboard-read': true,
  'clipboard-write': true,
  'display-capture': true,
  'speaker-selection': true,
  'window-management': true,
  'local-fonts': true,
  'id-detection': true
})

function defaultPermissionsPolicy () {
  return {
    sensitive: Object.assign({}, PP_SENSITIVE),
    // 若为 true，则敏感特性必须显式声明 () （连顶层都禁用）才算合规。
    requireDenySensitive: false,
    rejectControlChars: true
  }
}

function ppHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code <= 0x1F || code === 0x7F) return true
  }
  return false
}

function ppIsSpace (c) {
  return c === ' ' || c === '\t'
}

// 解析单个特性片段，如：geolocation=(self "https://a.example")
// 返回 { name, allowed:{wildcard,self,origins:[],denied,allByOmission}, error }
function parseFeature (chunk) {
  const text = chunk.trim()
  const out = {
    name: null,
    wildcard: false,
    self: false,
    origins: [],
    denied: false,
    allByOmission: false,
    present: true,
    error: null
  }
  const eq = text.indexOf('=')
  let namePart = text
  let listPart = null
  if (eq >= 0) {
    namePart = text.slice(0, eq).trim()
    listPart = text.slice(eq + 1).trim()
  }
  const name = namePart.toLowerCase()
  if (name === '') {
    out.error = 'empty-feature-name'
    return out
  }
  out.name = name

  if (listPart === null) {
    // 旧式：无 allowlist 表示任意来源可用。
    out.allByOmission = true
    return out
  }
  if (listPart === '*') {
    out.wildcard = true
    return out
  }
  if (listPart.charAt(0) !== '(' || listPart.charAt(listPart.length - 1) !== ')') {
    out.error = 'allowlist-not-parenthesized'
    return out
  }
  const inner = listPart.slice(1, -1)

  // 解析空格分隔的 token：self / src / 引号 origin。
  let i = 0
  let sawToken = false
  while (i < inner.length) {
    while (i < inner.length && ppIsSpace(inner.charAt(i))) i++
    if (i >= inner.length) break
    const c = inner.charAt(i)
    if (c === '"' || c === "'") {
      const quote = c
      let j = i + 1
      let origin = ''
      let closed = false
      while (j < inner.length) {
        if (inner.charAt(j) === quote) { closed = true; break }
        origin += inner.charAt(j)
        j++
      }
      if (!closed) {
        out.error = 'unterminated-origin-quote'
        return out
      }
      if (origin === '') {
        out.error = 'empty-origin'
        return out
      }
      out.origins.push(origin)
      sawToken = true
      i = j + 1
    } else {
      let j = i
      let tok = ''
      while (j < inner.length && !ppIsSpace(inner.charAt(j))) {
        tok += inner.charAt(j)
        j++
      }
      if (tok === 'self') {
        out.self = true
      } else if (tok === 'src' || tok === '*') {
        // 单独的 * 在括号内（不规范）也按通配处理。
        if (tok === '*') out.wildcard = true
        else out.origins.push('src')
      } else {
        out.origins.push(tok)
      }
      sawToken = true
      i = j
    }
  }
  if (!sawToken) {
    out.denied = true
  }
  return out
}

// 顶层解析：按逗号切分（origin 引号内不含逗号），逐特性解析。
function parsePermissionsPolicy (value) {
  const features = []
  const errors = []
  const parts = String(value).split(',')
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].trim() === '') {
      errors.push('empty-feature-chunk')
      continue
    }
    const f = parseFeature(parts[i])
    if (f.error) {
      errors.push(f.name + ':' + f.error)
    }
    features.push(f)
  }
  return { features: features, errors: errors }
}

class PermissionsPolicyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultPermissionsPolicy(), policy || {})
  }

  evaluate (headerValue) {
    const pol = this.policy
    const findings = []
    if (headerValue === null || headerValue === undefined) {
      findings.push({ reason: PP_REASON.MISSING })
      return { safe: false, features: [], findings }
    }
    const raw = String(headerValue)
    if (raw.trim() === '') {
      findings.push({ reason: PP_REASON.EMPTY })
      return { safe: false, features: [], findings }
    }
    if (pol.rejectControlChars && ppHasControlChar(raw)) {
      findings.push({ reason: PP_REASON.CONTROL_CHAR })
    }
    const parsed = parsePermissionsPolicy(raw)
    parsed.errors.forEach((e) => findings.push({ reason: PP_REASON.SYNTAX_ERROR, detail: e }))

    const byName = {}
    parsed.features.forEach((f) => {
      byName[f.name] = f
      if (f.wildcard) {
        findings.push({ reason: PP_REASON.WILDCARD, feature: f.name })
      }
      if (f.allByOmission) {
        findings.push({ reason: PP_REASON.ALLOW_ALL_OMITTED, feature: f.name })
      }
      // 除 self 以外的任何具体来源都视为第三方授权（含 src 占位/裸 origin）。
      if (f.origins.length > 0) {
        findings.push({
          reason: PP_REASON.THIRD_PARTY_ORIGIN,
          feature: f.name,
          origins: f.origins.slice()
        })
      }
    })

    if (pol.requireDenySensitive) {
      Object.keys(pol.sensitive).forEach((name) => {
        const f = byName[name]
        if (!f || !(f.denied)) {
          findings.push({ reason: PP_REASON.SENSITIVE_NOT_DISABLED, feature: name })
        }
      })
    }

    return {
      safe: findings.length === 0,
      features: parsed.features,
      byName: byName,
      findings: findings
    }
  }
}

module.exports = Object.freeze({
  PP_HEADER: PP_HEADER,
  PP_REASON: PP_REASON,
  PP_SENSITIVE: PP_SENSITIVE,
  defaultPermissionsPolicy: defaultPermissionsPolicy,
  parseFeature: parseFeature,
  parsePermissionsPolicy: parsePermissionsPolicy,
  PermissionsPolicyGuard: PermissionsPolicyGuard
})
