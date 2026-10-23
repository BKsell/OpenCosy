'use strict'

// srihashguard.js —— Subresource Integrity（SRI）完整性属性守卫。
//
// 威胁模型：
//   <script src>/<link href> 引第三方 CDN 资源，若没有 integrity，CDN 被攻破即可下发任意脚本；
//   有 integrity 但算法弱（sha1/MD5）、hash 与实际不匹配、crossorigin 缺失导致某些浏览器不执行校验，
//   都会让 SRI 失效。规则：
//     - 跨源脚本/样式必须带 integrity 且含至少一个强算法（sha256+，推荐 sha384/sha512）；
//     - 同源资源可放宽；
//     - integrity 多 hash 全部解析，任一弱算法给告警（强+弱并存时以强者为准）；
//     - 实际算出的摘要必须在声明集合里。
//   纯字符解析 integrity 描述符，不使用正则。

const SRI_REASON = Object.freeze({
  MISSING_INTEGRITY: 'cross-origin-resource-has-no-sri-integrity',
  WEAK_ALGORITHM: 'sri-uses-weak-hash-algorithm',
  MALFORMED: 'sri-integrity-descriptor-malformed',
  HASH_MISMATCH: 'resource-digest-not-in-sri-integrity-list',
  MISSING_CROSSORIGIN: 'sri-resource-missing-crossorigin-attribute'
})

const STRONG_ALGS = ['sha256', 'sha384', 'sha512']
const WEAK_ALGS = ['sha1', 'md5', 'md2']

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

function sriLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function sriIsSpace (c) {
  return c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f'
}

// integrity = 空格分隔的 "alg-base64" 描述符。
function sriParse (integrity) {
  const s = String(integrity || '')
  const descriptors = []
  let i = 0
  while (i < s.length) {
    while (i < s.length && sriIsSpace(s[i])) i++
    const start = i
    while (i < s.length && !sriIsSpace(s[i])) i++
    if (i > start) descriptors.push(s.slice(start, i))
  }
  const parsed = []
  let malformed = false
  for (const d of descriptors) {
    const dash = d.indexOf('-')
    if (dash <= 0) { malformed = true; continue }
    const alg = sriLower(d.slice(0, dash))
    const digest = d.slice(dash + 1)
    if (digest.length === 0) { malformed = true; continue }
    for (let k = 0; k < digest.length; k++) {
      if (BASE64.indexOf(digest[k]) < 0) { malformed = true; break }
    }
    parsed.push({ alg: alg, digest: digest, raw: d })
  }
  return { parsed: parsed, malformed: malformed || (descriptors.length === 0 && s.trim() !== '') }
}

class SriHashGuard {
  // in: { crossOrigin:bool, tag:'script'|'link', integrity, actualDigest, crossorigin }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const cross = inp.crossOrigin === true
    const integrityPresent = inp.integrity !== undefined && inp.integrity !== null && String(inp.integrity).trim() !== ''

    if (cross && !integrityPresent) findings.push({ reason: SRI_REASON.MISSING_INTEGRITY })
    if (!integrityPresent) {
      return { safe: findings.length === 0, findings: findings }
    }
    if (cross && inp.crossorigin === undefined) findings.push({ reason: SRI_REASON.MISSING_CROSSORIGIN })

    const p = sriParse(inp.integrity)
    if (p.malformed) findings.push({ reason: SRI_REASON.MALFORMED })
    let hasStrong = false
    for (const d of p.parsed) {
      if (STRONG_ALGS.indexOf(d.alg) >= 0) hasStrong = true
      if (WEAK_ALGS.indexOf(d.alg) >= 0) findings.push({ reason: SRI_REASON.WEAK_ALGORITHM, detail: d.alg })
    }
    // 没有任何一个强算法描述符（全是 sha1/未知算法）时，整体不满足强完整性。
    if (p.parsed.length > 0 && !hasStrong) findings.push({ reason: SRI_REASON.WEAK_ALGORITHM })
    if (inp.actualDigest) {
      const actual = String(inp.actualDigest)
      const hit = p.parsed.some((d) => d.alg + '-' + d.digest === actual || d.raw === actual)
      if (!hit) findings.push({ reason: SRI_REASON.HASH_MISMATCH })
    }
    return { safe: findings.length === 0, findings: findings, descriptors: p.parsed }
  }
}

module.exports = Object.freeze({
  SRI_REASON: SRI_REASON,
  STRONG_ALGS: STRONG_ALGS,
  sriParse: sriParse,
  SriHashGuard: SriHashGuard
})
