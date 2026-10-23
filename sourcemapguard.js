'use strict'

// sourcemapguard.js —— 生产环境 Source Map / sourceMappingURL 暴露守卫。
//
// 威胁模型：
//   浏览器内置页面、扩展脚本若在正式发布里带 //# sourceMappingURL=app.js.map 且 map 可访问，
//   等于把原始源码（含注释里的内部地址、密钥线索、未压缩逻辑）公开，便于攻击者审计与找漏洞；
//   data:application/json;base64 内联 map 同样泄露。开发环境需要 map，因此按环境区分。
//   本模块扫描 JS/CSS 文本尾部指令，并审计 .map 是否被引用、是否内联。纯字符查找，不使用正则。

const SM2_REASON = Object.freeze({
  SOURCEMAPPING_URL: 'production-asset-references-sourcemapping-url',
  INLINE_SOURCE_MAP: 'production-asset-embeds-inline-source-map',
  EXTERNAL_MAP_ACCESSIBLE: 'source-map-file-served-in-production',
  COMMENT_IN_ODD_PLACE: 'sourcemapping-directive-not-at-end-of-file'
})

const JS_DIRECTIVE = '//# sourceMappingURL='
const CSS_DIRECTIVE = '/*# sourceMappingURL='

function smLastIndex (s, sub) {
  return s.lastIndexOf(sub)
}

function smFirstLine (s) {
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\r' || s[i] === '\n') return s.slice(0, i)
  }
  return s
}

function smTrim (s) {
  let a = 0
  let b = s.length
  while (a < b && (s[a] === ' ' || s[a] === '\t' || s[a] === '\r' || s[a] === '\n')) a++
  while (b > a && (s[b - 1] === ' ' || s[b - 1] === '\t' || s[b - 1] === '\r' || s[b - 1] === '\n')) b--
  return s.slice(a, b)
}

class SourceMapGuard {
  // asset: { kind:'js'|'css', text, production:bool }
  evaluate (asset) {
    const a = asset || {}
    const findings = []
    const text = String(a.text || '')
    const directive = a.kind === 'css' ? CSS_DIRECTIVE : JS_DIRECTIVE
    const idx = smLastIndex(text, directive)
    if (idx < 0) return { safe: true, findings: findings }

    // 开发环境允许带 map
    if (a.production === false) return { safe: true, findings: findings }

    const tail = smTrim(text.slice(idx + directive.length))
    let target = tail
    if (a.kind === 'css') {
      const close = target.indexOf('*/')
      if (close >= 0) target = target.slice(0, close)
    } else {
      target = smFirstLine(target)
    }
    const value = smTrim(target)
    if (value.indexOf('data:') === 0) {
      findings.push({ reason: SM2_REASON.INLINE_SOURCE_MAP })
    } else {
      findings.push({ reason: SM2_REASON.SOURCEMAPPING_URL, detail: value })
    }
    // 指令后若还有实质内容，说明指令没在文件末尾（异常放置）
    const afterDirective = text.slice(idx + directive.length)
    const lines = afterDirective.split('\n')
    if (lines.length > 2) findings.push({ reason: SM2_REASON.COMMENT_IN_ODD_PLACE })
    return { safe: findings.length === 0, findings: findings }
  }

  // 判断一个 map 资源是否不应在生产环境对外提供。
  assessMapServed (production) {
    if (production === false) return { safe: true, findings: [] }
    return { safe: false, findings: [{ reason: SM2_REASON.EXTERNAL_MAP_ACCESSIBLE }] }
  }
}

module.exports = Object.freeze({
  SM2_REASON: SM2_REASON,
  SourceMapGuard: SourceMapGuard
})
