'use strict'

// jsonbodyguard.js —— 不可信 JSON 响应体的有界解析守卫（深度/重复键/体量/数字词法）。
//
// 威胁模型：
//   浏览器解析版本清单、配置、扩展响应等不可信 JSON。直接 JSON.parse 的问题：
//     - 极深嵌套触发栈溢出/DoS；
//     - 同一对象内重复键，后者静默覆盖前者（{"role":"user","role":"admin"}），
//       而其它语言/手写安全检查可能取前者 → 校验与执行不一致导致绕过；
//     - 超长字符串、畸形数字、总体量过大。
//   本模块在构造对象前对原始文本做单遍有界走查（同时保留可返回的已解析值），
//   重复键比较做 JSON 转义还原，手写词法状态机，不使用正则。

const JB_REASON = Object.freeze({
  TOO_LARGE: 'json-body-byte-size-over-limit',
  NESTING_DEEP: 'json-nesting-depth-over-limit',
  DUPLICATE_KEY: 'json-object-has-duplicate-key',
  STRING_OVERLONG: 'json-string-value-over-limit',
  NUMBER_INVALID: 'json-number-malformed',
  PARSE_FAILED: 'json-body-not-valid-json',
  KEY_DECODE_FAILED: 'json-key-escape-sequence-malformed'
})

function jbDefaultPolicy () {
  return { maxBytes: 8 * 1024 * 1024, maxDepth: 32, maxStringLength: 1024 * 1024 }
}

function jbDecodeKey (raw) {
  try {
    return JSON.parse('"' + raw + '"')
  } catch (e) {
    return null
  }
}

// 单遍走查。返回 { findings }，findings 去重保序。
function jbScan (text, policy) {
  const findings = []
  const seenReason = new Set()
  function add (reason, detail) {
    if (!seenReason.has(reason)) {
      seenReason.add(reason)
      findings.push(detail === undefined ? { reason: reason } : { reason: reason, detail: detail })
    }
  }

  if (text.length > policy.maxBytes) add(JB_REASON.TOO_LARGE, String(text.length))

  const stack = [] // { isObject, keys:Set, state }
  let depth = 0
  let i = 0
  const n = text.length

  function skipWs () {
    while (i < n) {
      const c = text[i]
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++
      else break
    }
  }

  // 读取字符串（进入时 text[i]==='"'），i 停在闭引号后一格。返回引号内原文。
  function readString () {
    i++ // 开引号
    let raw = ''
    let len = 0
    while (i < n) {
      const c = text[i]
      if (c === '\\') {
        raw += c
        i++
        if (i >= n) { add(JB_REASON.PARSE_FAILED); return raw }
        raw += text[i]
        i++
        len++
        continue
      }
      if (c === '"') { i++; return raw }
      if (c.charCodeAt(0) < 0x20) add(JB_REASON.PARSE_FAILED)
      raw += c
      len++
      i++
      if (len > policy.maxStringLength) add(JB_REASON.STRING_OVERLONG)
    }
    add(JB_REASON.PARSE_FAILED)
    return raw
  }

  // 读取裸 token（true/false/null/number），做数字词法检查。
  function readLiteral () {
    const start = i
    while (i < n) {
      const c = text[i]
      if (c === ',' || c === '}' || c === ']' || c === ' ' || c === '\t' || c === '\n' || c === '\r') break
      i++
    }
    const lit = text.slice(start, i)
    const first = lit[0]
    if (first === 't' || first === 'f' || first === 'n') {
      if (lit !== 'true' && lit !== 'false' && lit !== 'null') add(JB_REASON.PARSE_FAILED)
      return
    }
    if (!jbValidNumber(lit)) add(JB_REASON.NUMBER_INVALID, lit)
  }

  // 期望读一个值（字符串/对象/数组/字面量）。
  function readValue () {
    skipWs()
    if (i >= n) { add(JB_REASON.PARSE_FAILED); return }
    const c = text[i]
    if (c === '"') { readString(); return }
    if (c === '{' || c === '[') { openContainer(c); return }
    readLiteral()
  }

  function openContainer (c) {
    depth++
    if (depth > policy.maxDepth) add(JB_REASON.NESTING_DEEP)
    const frame = { isObject: c === '{', keys: new Set(), afterOpenOrComma: true }
    stack.push(frame)
    i++
    skipWs()
    if (frame.isObject) { readObjectBody(frame) } else { readArrayBody(frame) }
  }

  function readObjectBody (frame) {
    if (text[i] === '}') { i++; stack.pop(); depth--; afterValue(); return }
    while (i < n) {
      skipWs()
      if (text[i] !== '"') { add(JB_REASON.PARSE_FAILED); return }
      const keyRaw = readString()
      const key = jbDecodeKey(keyRaw)
      if (key === null) { add(JB_REASON.KEY_DECODE_FAILED) } else if (frame.keys.has(key)) {
        add(JB_REASON.DUPLICATE_KEY, key)
      } else {
        frame.keys.add(key)
      }
      skipWs()
      if (text[i] !== ':') { add(JB_REASON.PARSE_FAILED); return }
      i++
      readValue()
      finishMember(frame)
      if (frame._closed) return
    }
  }

  function readArrayBody (frame) {
    if (text[i] === ']') { i++; stack.pop(); depth--; afterValue(); return }
    while (i < n) {
      readValue()
      finishMember(frame)
      if (frame._closed) return
    }
  }

  // 成员结束后处理 , 或闭合符。
  function finishMember (frame) {
    skipWs()
    const c = text[i]
    if (c === ',') { i++; return }
    const close = frame.isObject ? '}' : ']'
    if (c === close) {
      i++
      stack.pop()
      depth--
      frame._closed = true
      afterValue()
      return
    }
    add(JB_REASON.PARSE_FAILED)
  }

  // 子容器闭合后，当前位置可能停在外层对象需要逗号/闭合处；这里不推进，交给外层循环。
  function afterValue () {}

  skipWs()
  if (n === 0) { add(JB_REASON.PARSE_FAILED); return findings }
  const c = text[i]
  if (c === '{' || c === '[') {
    openContainer(c)
  } else {
    readValue()
  }
  skipWs()
  if (i < n && stack.length === 0) add(JB_REASON.PARSE_FAILED)
  if (depth !== 0) add(JB_REASON.PARSE_FAILED)
  return findings
}

// 严格 JSON 数字词法：-?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
function jbValidNumber (s) {
  let k = 0
  if (s[k] === '-') k++
  if (k >= s.length) return false
  if (s[k] === '0') {
    k++
  } else if (s[k] >= '1' && s[k] <= '9') {
    while (k < s.length && s[k] >= '0' && s[k] <= '9') k++
  } else {
    return false
  }
  if (s[k] === '.') {
    k++
    if (!(s[k] >= '0' && s[k] <= '9')) return false
    while (k < s.length && s[k] >= '0' && s[k] <= '9') k++
  }
  if (s[k] === 'e' || s[k] === 'E') {
    k++
    if (s[k] === '+' || s[k] === '-') k++
    if (!(s[k] >= '0' && s[k] <= '9')) return false
    while (k < s.length && s[k] >= '0' && s[k] <= '9') k++
  }
  return k === s.length
}

class JsonBodyGuard {
  constructor (policy) {
    this.policy = Object.assign({}, jbDefaultPolicy(), policy || {})
  }

  // 返回 { safe, findings, value }；仅在结构走查无致命问题时才返回解析值。
  parse (text) {
    const src = String(text)
    const findings = jbScan(src, this.policy)
    if (findings.some((f) => f.reason === JB_REASON.PARSE_FAILED || f.reason === JB_REASON.TOO_LARGE)) {
      return { safe: false, findings: findings, value: undefined }
    }
    let value
    try {
      value = JSON.parse(src)
    } catch (e) {
      return { safe: false, findings: findings.concat([{ reason: JB_REASON.PARSE_FAILED }]), value: undefined }
    }
    return { safe: findings.length === 0, findings: findings, value: value }
  }
}

module.exports = Object.freeze({
  JB_REASON: JB_REASON,
  jbDefaultPolicy: jbDefaultPolicy,
  jbValidNumber: jbValidNumber,
  JsonBodyGuard: JsonBodyGuard
})
