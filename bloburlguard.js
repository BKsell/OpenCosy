'use strict'

// bloburlguard.js —— blob:/data: URL 的生命周期与导航守卫。
//
// 威胁模型：
//   页面用 URL.createObjectURL 生成 blob:https://origin/uuid，或直接用 data: URL。风险：
//     - blob URL 长期不 revoke，跨导航仍可访问其中的敏感数据；
//     - 把 blob:/data: 直接赋给顶层 window.location 或 <a download>/window.open，
//       data:text/html 会以"不透明来源"执行脚本（旧浏览器里甚至继承导航源）；
//     - 用 data: URL 承载下载却声明可执行 MIME（text/html、image/svg+xml）。
//   本模块审计 URL scheme、MIME 与 revoke 状态。纯字符判定，不使用正则。

const BU_REASON = Object.freeze({
  BLOB_NAVIGATION: 'navigation-to-blob-or-data-url',
  DATA_EXECUTABLE_MIME: 'data-url-carries-executable-or-active-mime',
  BLOB_NOT_REVOKED: 'blob-url-never-revoked-before-unload',
  DATA_URL_OVERLONG: 'data-url-payload-too-long',
  ORIGIN_MISMATCH: 'blob-url-origin-does-not-match-page'
})

const EXEC_MIMES = ['text/html', 'application/xhtml+xml', 'image/svg+xml', 'application/javascript', 'text/javascript']

function buLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function buScheme (url) {
  const colon = String(url).indexOf(':')
  if (colon < 0) return ''
  return buLower(String(url).slice(0, colon))
}

// data:[<mediatype>][;base64],<data>
function buDataMime (url) {
  const s = String(url)
  const comma = s.indexOf(',')
  if (comma < 0) return ''
  const head = s.slice(5, comma) // 去掉 'data:'
  const semi = head.indexOf(';')
  const mime = semi >= 0 ? head.slice(0, semi) : head
  return buLower(mime.trim())
}

class BlobUrlGuard {
  constructor () {
    this.live = new Set()
  }

  created (url, origin) {
    this.live.add(url)
    return { url: url, origin: origin }
  }

  revoked (url) {
    this.live.delete(url)
  }

  // in: { url, asNavigation:bool, pageOrigin, dataMaxLength }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const url = String(inp.url || '')
    const scheme = buScheme(url)

    if (inp.asNavigation && (scheme === 'blob' || scheme === 'data')) {
      findings.push({ reason: BU_REASON.BLOB_NAVIGATION })
    }
    if (scheme === 'data') {
      const mime = buDataMime(url)
      if (EXEC_MIMES.indexOf(mime) >= 0) findings.push({ reason: BU_REASON.DATA_EXECUTABLE_MIME, detail: mime })
      const comma = url.indexOf(',')
      const payloadLen = comma >= 0 ? url.length - comma - 1 : 0
      const max = typeof inp.dataMaxLength === 'number' ? inp.dataMaxLength : 2 * 1024 * 1024
      if (payloadLen > max) findings.push({ reason: BU_REASON.DATA_URL_OVERLONG })
    }
    if (scheme === 'blob' && inp.pageOrigin && inp.blobOrigin) {
      if (buLower(String(inp.pageOrigin)) !== buLower(String(inp.blobOrigin))) {
        findings.push({ reason: BU_REASON.ORIGIN_MISMATCH })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 页面卸载前调用：返回仍未 revoke 的 blob URL。
  auditBeforeUnload () {
    const leaked = Array.from(this.live)
    const findings = leaked.length > 0
      ? leaked.map(() => ({ reason: BU_REASON.BLOB_NOT_REVOKED }))
      : []
    return { safe: leaked.length === 0, findings: findings, leaked: leaked }
  }
}

module.exports = Object.freeze({
  BU_REASON: BU_REASON,
  EXEC_MIMES: EXEC_MIMES,
  BlobUrlGuard: BlobUrlGuard
})
