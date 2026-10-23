'use strict'

// mimesniffguard.js —— 响应 Content-Type 与 X-Content-Type-Options:nosniff 一致性守卫。
//
// 威胁模型：
//   没有 nosniff 时，浏览器会"内容嗅探"：一个被标记为 text/plain 的文件若以 <script> 或
//   <html> 开头，会被当 HTML/JS 执行（MIME confusion → 存储型 XSS、同源脚本执行）。尤其用户
//   上传/下载镜像站点上的图片、文本若可同源访问，危险更大。
//   本模块审计：
//     - 是否缺少 nosniff；
//     - 声明的 MIME 与响应体"魔数/起始文本"是否一致；
//     - text/html、application/javascript、image/svg+xml 等可执行/可内嵌 SVG 类型在不应出现处出现。
//   纯字节判定，不使用正则。

const MS_REASON = Object.freeze({
  NOSNIFF_MISSING: 'response-missing-x-content-type-options-nosniff',
  MIME_MAGIC_MISMATCH: 'declared-mime-does-not-match-content-magic',
  MIME_EMPTY: 'response-content-type-empty',
  HTML_SERVED_AS_NON_HTML: 'html-content-served-as-non-executable-type',
  SVG_ACTIVE: 'image-svg-xml-served-sniffable-active-content'
})

const MAGIC = [
  { bytes: [0xFF, 0xD8, 0xFF], mime: 'image/jpeg' },
  { bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], mime: 'image/png' },
  { ascii: 'GIF87a', mime: 'image/gif' },
  { ascii: 'GIF89a', mime: 'image/gif' },
  { ascii: '%PDF-', mime: 'application/pdf' },
  { ascii: 'PK', mime: 'application/zip' }
]

// 注：8 字节完整 PNG 签名在前，4 字节短签名兜底（仅看到文件头一部分时也能识别）。
const MAGIC_EXTRA = [
  { bytes: [0x89, 0x50, 0x4E, 0x47], mime: 'image/png' }
]

function msStartsWithAscii (buf, text) {
  if (buf.length < text.length) return false
  for (let i = 0; i < text.length; i++) {
    if (buf[i] !== text.charCodeAt(i)) return false
  }
  return true
}

function msDetectMagic (buf) {
  for (const list of [MAGIC, MAGIC_EXTRA]) {
    for (const m of list) {
      if (m.bytes) {
        if (buf.length < m.bytes.length) continue
        let ok = true
        for (let i = 0; i < m.bytes.length; i++) {
          if (buf[i] !== m.bytes[i]) { ok = false; break }
        }
        if (ok) return m.mime
      } else if (msStartsWithAscii(buf, m.ascii)) {
        return m.mime
      }
    }
  }
  return null
}

// 跳过 BOM/空白后，判断文本是否以 <html/<script/<iframe/<!doctype 起始。
function msLooksLikeHtml (buf) {
  let i = 0
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) i = 3
  while (i < buf.length && (buf[i] === 0x20 || buf[i] === 0x09 || buf[i] === 0x0A || buf[i] === 0x0D)) i++
  const head = String.fromCharCode.apply(null, buf.slice(i, i + 10)).toLowerCase()
  return head.indexOf('<html') === 0 ||
    head.indexOf('<script') === 0 ||
    head.indexOf('<iframe') === 0 ||
    head.indexOf('<!do') === 0 ||
    head.indexOf('<?xml') === 0
}

class MimeSniffGuard {
  // in: { contentType, nosniff:bool, bodyBytes:number[] }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const ct = String(inp.contentType || '').toLowerCase()
    const base = ct.split(';')[0].trim()

    if (!base) findings.push({ reason: MS_REASON.MIME_EMPTY })
    if (inp.nosniff !== true) findings.push({ reason: MS_REASON.NOSNIFF_MISSING })

    const buf = Array.isArray(inp.bodyBytes) ? inp.bodyBytes : []
    if (buf.length > 0) {
      const magicMime = msDetectMagic(buf)
      if (magicMime && base && base !== magicMime) {
        findings.push({ reason: MS_REASON.MIME_MAGIC_MISMATCH, detail: base + '!=' + magicMime })
      }
      if (msLooksLikeHtml(buf) &&
          base &&
          base !== 'text/html' &&
          base !== 'application/xhtml+xml') {
        findings.push({ reason: MS_REASON.HTML_SERVED_AS_NON_HTML, detail: base })
      }
      if (base === 'image/svg+xml') findings.push({ reason: MS_REASON.SVG_ACTIVE })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  MS_REASON: MS_REASON,
  msDetectMagic: msDetectMagic,
  msLooksLikeHtml: msLooksLikeHtml,
  MimeSniffGuard: MimeSniffGuard
})
