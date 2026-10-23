'use strict'

// linkrelguard.js —— target="_blank" 链接的 rel 安全守卫（反向 tabnabbing）。
//
// 威胁模型：
//   用 target="_blank"（或 window.open）打开外部页且不带 rel="noopener" 时，新页面持有
//   window.opener，可把原页面 location 改成钓鱼页（tab-nabbing），旧浏览器还共享部分进程。
//   noreferrer 同时具备 noopener 的断引用效果并隐藏 Referer。
// 判定：
//   - target 为 _blank 或在新窗口打开 → 必须有 noopener（或 noreferrer）；
//   - 跨源链接缺少两者 → 命中；同源可按策略放宽；
//   - 反向写法 opene（拼写错误）不生效。

const LR_REASON = Object.freeze({
  TARGET_BLANK_NO_NOOPENER: 'lr-target-blank-without-noopener',
  MISSING_REL: 'lr-missing-rel',
  UNKNOWN_REL_TOKEN: 'lr-unknown-rel-token'
})

function defaultLinkRelPolicy () {
  return { sameOriginExempt: true, rejectUnknown: false }
}

function lrTokens (rel) {
  if (!rel) return []
  const s = String(rel)
  const out = []
  let cur = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charAt(i)
    if (c === ' ' || c === '\t') {
      if (cur !== '') { out.push(cur.toLowerCase()); cur = '' }
    } else {
      cur += c
    }
  }
  if (cur !== '') out.push(cur.toLowerCase())
  return out
}

function lrOriginOf (url) {
  if (!url) return ''
  const s = String(url)
  const protoEnd = s.indexOf('://')
  if (protoEnd < 0) return ''
  const rest = s.slice(protoEnd + 3)
  const slash = rest.indexOf('/')
  const host = slash < 0 ? rest : rest.slice(0, slash)
  return s.slice(0, protoEnd + 3) + host
}

function lrIsCrossOrigin (fromUrl, toUrl) {
  const a = lrOriginOf(fromUrl)
  const b = lrOriginOf(toUrl)
  if (!a || !b) return true // 无法判定时按跨源保守处理
  return a.toLowerCase() !== b.toLowerCase()
}

class LinkRelGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultLinkRelPolicy(), policy || {})
  }

  // link: { target, rel, href, fromHref }
  evaluate (link) {
    const l = link || {}
    const findings = []
    const target = (l.target || '').toLowerCase()
    const opensNew = target === '_blank' || l.forceNewWindow === true
    if (!opensNew) {
      return { safe: true, opensNew: false, findings }
    }
    const cross = lrIsCrossOrigin(l.fromHref, l.href)
    // 同源且策略豁免时，即使缺 rel 也放行。
    if (this.policy.sameOriginExempt && !cross) {
      return { safe: true, opensNew: true, crossOrigin: false, findings }
    }
    const rels = lrTokens(l.rel)
    if (rels.length === 0) {
      findings.push({ reason: LR_REASON.MISSING_REL })
    }
    const hasNoopener = rels.indexOf('noopener') >= 0
    const hasNoreferrer = rels.indexOf('noreferrer') >= 0
    if (!hasNoopener && !hasNoreferrer) {
      findings.push({ reason: LR_REASON.TARGET_BLANK_NO_NOOPENER })
    }
    return { safe: findings.length === 0, opensNew: true, crossOrigin: cross, findings }
  }
}

module.exports = Object.freeze({
  LR_REASON: LR_REASON,
  defaultLinkRelPolicy: defaultLinkRelPolicy,
  lrTokens: lrTokens,
  lrOriginOf: lrOriginOf,
  LinkRelGuard: LinkRelGuard
})
