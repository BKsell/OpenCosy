'use strict'

// corpguard.js —— Cross-Origin-Resource-Policy（跨源资源加载策略）守卫。
//
// 威胁模型：
//   CORP 控制资源能被哪些跨源文档加载（缓解 Spectre 类跨源读、跨站脚本包含）：
//     - 缺省：历史上任意跨源可 <script>/<img>/fetch（no-cors）包含；
//     - same-origin：只允许同源文档；
//     - same-site：允许同站（含子域）；
//     - cross-origin：显式允许任意跨源（等于公开，需确认确实是公开资源）。
//   含用户私有数据的响应若为 cross-origin/缺省会被任意跨站包含。纯字符判定，不使用正则。

const CORP_REASON = Object.freeze({
  MISSING_ON_PRIVATE: 'private-resource-has-no-cross-origin-resource-policy',
  CROSS_ORIGIN_ON_PRIVATE: 'private-resource-marked-corp-cross-origin',
  UNKNOWN_VALUE: 'corp-value-unrecognized',
  SAME_SITE_ON_STRICT: 'strict-isolation-resource-only-same-origin-but-same-site-set'
})

const KNOWN = ['same-origin', 'same-site', 'cross-origin']

function corpLower (s) {
  return String(s).trim().toLowerCase()
}

class CorpGuard {
  // in: { header, resourceClass:'private'|'public'|'static', strictIsolation }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const cls = corpLower(String(inp.resourceClass || 'private'))
    if (inp.header === undefined || inp.header === null || String(inp.header).trim() === '') {
      if (cls === 'private') findings.push({ reason: CORP_REASON.MISSING_ON_PRIVATE })
      return { safe: findings.length === 0, findings: findings }
    }
    const v = corpLower(inp.header)
    if (KNOWN.indexOf(v) < 0) findings.push({ reason: CORP_REASON.UNKNOWN_VALUE, detail: v })
    if (cls === 'private' && v === 'cross-origin') findings.push({ reason: CORP_REASON.CROSS_ORIGIN_ON_PRIVATE })
    if (inp.strictIsolation === true && v === 'same-site') findings.push({ reason: CORP_REASON.SAME_SITE_ON_STRICT })
    return { safe: findings.length === 0, findings: findings, value: v }
  }
}

module.exports = Object.freeze({
  CORP_REASON: CORP_REASON,
  KNOWN: KNOWN,
  CorpGuard: CorpGuard
})
