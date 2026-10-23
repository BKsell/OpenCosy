'use strict'

// subresourceintegrityguard.js —— 子资源完整性 SRI（integrity 属性）守卫。
//
// 威胁模型：
//   从 CDN/第三方加载的 <script>/<link rel=stylesheet> 若不带 integrity，一旦 CDN 被篡改或
//   域名接管，恶意脚本会直接在本页源下执行。SRI 要求浏览器校验哈希。问题：
//     - 跨源 script/css 缺 integrity：无篡改检测；
//     - 使用弱算法 sha1/md5（甚至 md5/sha1 已不被 SRI 接受）；
//     - 给了 integrity 却没有 crossorigin：跨源资源无法完成 CORS 校验，SRI 不生效；
//     - 空 integrity / 仅算法无哈希值；
//     - data: URI 不需要 SRI（同源派生），可豁免。

const SRI_REASON = Object.freeze({
  MISSING_INTEGRITY: 'sri-missing-integrity',
  WEAK_ALGORITHM: 'sri-weak-algorithm',
  EMPTY_HASH: 'sri-empty-hash',
  MALFORMED: 'sri-malformed-expression',
  MISSING_CROSSORIGIN: 'sri-missing-crossorigin'
})

const SRI_WEAK = Object.freeze({ md5: true, sha1: true })
const SRI_STRONG = Object.freeze({ sha256: true, sha384: true, sha512: true })

function defaultSriPolicy () {
  return {
    requireForCrossOrigin: true,
    requireCrossOriginAttr: true,
    // 同源资源默认不强制 SRI（传输可信）；可打开。
    requireForSameOrigin: false
  }
}

function sriScheme (url) {
  const s = String(url || '')
  const i = s.indexOf(':')
  return i <= 0 ? '' : s.slice(0, i).toLowerCase()
}

function sriOriginOf (url) {
  const s = String(url || '')
  const i = s.indexOf('://')
  if (i < 0) return ''
  const rest = s.slice(i + 3)
  const slash = rest.indexOf('/')
  return s.slice(0, i + 3) + (slash < 0 ? rest : rest.slice(0, slash)).toLowerCase()
}

// 解析 integrity 串：多个 "alg-base64" 用空格分隔。
// 返回 { entries:[{alg,hash}], weak:[], empty:[], malformed:[] }
function parseIntegrity (value) {
  const res = { entries: [], weak: [], empty: [], malformed: [] }
  if (!value) return res
  const s = String(value)
  let cur = ''
  const toks = []
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i)
    if (c === ' ' || c === '\t') { if (cur !== '') { toks.push(cur); cur = '' } } else cur += c
  }
  if (cur !== '') toks.push(cur)
  toks.forEach((t) => {
    const dash = t.indexOf('-')
    if (dash <= 0) { res.malformed.push(t); return }
    const alg = t.slice(0, dash).toLowerCase()
    const hash = t.slice(dash + 1)
    if (hash === '') { res.empty.push(t); return }
    res.entries.push({ alg: alg, hash: hash })
    if (SRI_WEAK[alg]) res.weak.push(alg)
  })
  return res
}

class SubresourceIntegrityGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultSriPolicy(), policy || {})
  }

  // asset: { tag:'script'|'link', url, integrity, crossOrigin, baseOrigin }
  evaluate (asset) {
    const a = asset || {}
    const pol = this.policy
    const findings = []
    const tag = String(a.tag || '').toLowerCase()
    const applies = tag === 'script' || (tag === 'link') // link 调用方确保 rel=stylesheet
    if (!applies) return { safe: true, applies: false, findings }

    const scheme = sriScheme(a.url)
    if (scheme === 'data' || scheme === 'blob' || scheme === '') {
      return { safe: true, applies: true, exempt: true, findings }
    }
    const cross = sriOriginOf(a.url) !== String(a.baseOrigin || '').toLowerCase()
    const need = cross ? pol.requireForCrossOrigin : pol.requireForSameOrigin
    if (!need) return { safe: true, applies: true, crossOrigin: cross, findings }

    if (a.integrity === null || a.integrity === undefined || String(a.integrity).trim() === '') {
      findings.push({ reason: SRI_REASON.MISSING_INTEGRITY, url: a.url })
      return { safe: false, findings }
    }
    const parsed = parseIntegrity(a.integrity)
    parsed.malformed.forEach(() => findings.push({ reason: SRI_REASON.MALFORMED }))
    parsed.empty.forEach(() => findings.push({ reason: SRI_REASON.EMPTY_HASH }))
    if (parsed.weak.length > 0) findings.push({ reason: SRI_REASON.WEAK_ALGORITHM, algorithms: parsed.weak })
    const hasStrong = parsed.entries.some((e) => SRI_STRONG[e.alg])
    if (!hasStrong && parsed.entries.length > 0) {
      findings.push({ reason: SRI_REASON.WEAK_ALGORITHM, algorithms: parsed.entries.map((e) => e.alg) })
    }
    if (cross && pol.requireCrossOriginAttr && a.crossOrigin !== true &&
        String(a.crossOrigin || '').toLowerCase() !== 'anonymous' &&
        String(a.crossOrigin || '').toLowerCase() !== 'use-credentials') {
      findings.push({ reason: SRI_REASON.MISSING_CROSSORIGIN })
    }
    return { safe: findings.length === 0, crossOrigin: cross, entries: parsed.entries, findings }
  }
}

module.exports = Object.freeze({
  SRI_REASON: SRI_REASON,
  SRI_STRONG: SRI_STRONG,
  SRI_WEAK: SRI_WEAK,
  defaultSriPolicy: defaultSriPolicy,
  parseIntegrity: parseIntegrity,
  SubresourceIntegrityGuard: SubresourceIntegrityGuard
})
