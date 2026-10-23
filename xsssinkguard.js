'use strict'

// xsssinkguard.js —— DOM XSS 危险注入点（sink）与输入来源审计。
//
// 威胁模型：
//   渲染进程里把不可信数据塞给危险 sink 是 DOM XSS 根因：
//     - element.innerHTML / outerHTML、document.write、el.srcdoc、el.href='javascript:'；
//     - setTimeout/setInterval 接字符串、new Function、eval；
//     - 通过 location 赋值跳到 javascript:；
//     - 数据源来自 location.hash/search、postMessage、localStorage、网络响应（不可信源）。
//   本模块做静态/审计式判定：给定 sink 名与数据来源/形态，判断是否安全。纯字符匹配，不使用正则。

const XS_REASON = Object.freeze({
  HTML_SINK_WITH_RAW_INPUT: 'untrusted-input-written-to-html-sink',
  DOC_WRITE: 'document-write-receives-untrusted-data',
  SCRIPT_STRING_SINK: 'string-passed-to-eval-function-or-timer',
  JAVASCRIPT_NAV: 'navigation-to-javascript-url-from-data',
  UNTRUSTED_SOURCE: 'data-comes-from-untrusted-source',
  NO_SANITIZER: 'html-sink-used-without-sanitizer-or-contextual-escaping'
})

const HTML_SINKS = ['innerhtml', 'outerhtml', 'srcdoc', 'insertadjacenthtml']
const CODE_STRING_SINKS = ['eval', 'newfunction', 'settimeout-string', 'setinterval-string']
const UNTRUSTED_SOURCES = [
  'location.hash', 'location.search', 'location.href', 'document.url',
  'document.referrer', 'postmessage', 'localstorage', 'sessionstorage',
  'fetch-response', 'xhr-response', 'window.name', 'cookie'
]

function xsLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

class XssSinkGuard {
  // in: { sink, source, sanitized:bool, value, isJavascriptUrl }
  evaluate (input) {
    const inp = input || {}
    const sink = xsLower(String(inp.sink || ''))
    const source = xsLower(String(inp.source || ''))
    const findings = []
    const untrustedSource = UNTRUSTED_SOURCES.indexOf(source) >= 0

    const isHtml = HTML_SINKS.indexOf(sink) >= 0
    const isDocWrite = sink === 'document.write' || sink === 'document.writeln'
    const isCodeString = CODE_STRING_SINKS.indexOf(sink) >= 0
    const isNavSink = sink === 'location.href' || sink === 'location.assign'
    // 安全赋值类 sink（textContent、setAttribute 到非 URL 属性等）即便来源不可信也不产生 XSS。
    if (!isHtml && !isDocWrite && !isCodeString && !isNavSink && inp.isJavascriptUrl !== true) {
      return { safe: true, findings: findings }
    }
    if (untrustedSource) findings.push({ reason: XS_REASON.UNTRUSTED_SOURCE, detail: source })

    if (isHtml) {
      if (untrustedSource || inp.untrusted === true) {
        findings.push({ reason: XS_REASON.HTML_SINK_WITH_RAW_INPUT })
        if (inp.sanitized !== true) findings.push({ reason: XS_REASON.NO_SANITIZER })
      } else if (inp.sanitized !== true && inp.untrusted !== false) {
        // 来源未知且未声明已净化，保守提示。
        findings.push({ reason: XS_REASON.NO_SANITIZER })
      }
    }
    if (isDocWrite) {
      if (untrustedSource || inp.untrusted !== false) findings.push({ reason: XS_REASON.DOC_WRITE })
    }
    if (isCodeString) {
      if (untrustedSource || inp.untrusted !== false) findings.push({ reason: XS_REASON.SCRIPT_STRING_SINK })
    }
    if (inp.isJavascriptUrl === true ||
        isNavSink && xsLower(String(inp.value || '')).indexOf('javascript:') === 0) {
      findings.push({ reason: XS_REASON.JAVASCRIPT_NAV })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  XS_REASON: XS_REASON,
  HTML_SINKS: HTML_SINKS,
  UNTRUSTED_SOURCES: UNTRUSTED_SOURCES,
  XssSinkGuard: XssSinkGuard
})
