'use strict'

// contentdispositionguard.js —— Content-Disposition 响应头安全守卫。
//
// 威胁模型：
//   下载文件名来自用户/外部输入时，错误的 Content-Disposition 会导致：
//     - 头注入：filename 里含 CR/LF 可截断/追加响应头（响应拆分）；
//     - 路径穿越：filename="../../etc/passwd" 或带绝对盘符/反斜杠，配合有缺陷的保存逻辑写出界；
//     - 可执行扩展：.exe/.scr/.bat/.html（HTML 可在下载目录被打开触发本地同源问题）；
//     - filename* 编码（RFC 5987）与普通 filename 不一致，可用于欺骗；
//     - 引号未转义破坏头结构。
//
// 本模块解析 disposition 类型与文件名并给出风险结论，供下载入口统一过滤。

const CD_REASON = Object.freeze({
  EMPTY: 'cd-empty',
  UNKNOWN_TYPE: 'cd-unknown-disposition',
  CRLF_INJECTION: 'cd-crlf-injection',
  PATH_TRAVERSAL: 'cd-path-traversal',
  ABSOLUTE_PATH: 'cd-absolute-path',
  EXECUTABLE_EXTENSION: 'cd-executable-extension',
  FILENAME_MISMATCH: 'cd-filename-star-mismatch',
  UNC_PATH: 'cd-unc-path',
  CONTROL_CHAR: 'cd-control-char'
})

const CD_EXEC_EXT = Object.freeze({
  '.exe': true, '.scr': true, '.bat': true, '.cmd': true, '.com': true,
  '.msi': true, '.ps1': true, '.jar': true, '.html': true, '.htm': true,
  '.hta': true, '.js': true, '.vbs': true, '.dll': true, '.lnk': true
})

function defaultCdPolicy () {
  return {
    allowedTypes: { inline: true, attachment: true },
    rejectExecutable: true,
    rejectControlChars: true
  }
}

function cdHasControlChar (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x1F || c === 0x7F) return true
  }
  return false
}

// 从头值里取 filename 与 filename*（RFC5987）。纯字符解析。
function cdParse (raw) {
  const s = String(raw || '')
  const parts = s.split(';')
  const type = parts[0].trim().toLowerCase()
  let filename = null
  let filenameStar = null
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i].trim()
    if (seg === '') continue
    const lower = seg.toLowerCase()
    if (lower.indexOf('filename*=') === 0) {
      filenameStar = cdStripQuotes(seg.slice('filename*='.length).trim())
    } else if (lower.indexOf('filename=') === 0) {
      filename = cdStripQuotes(seg.slice('filename='.length).trim())
    }
  }
  return { type: type, filename: filename, filenameStar: filenameStar }
}

function cdStripQuotes (v) {
  if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
    return v.slice(1, v.length - 1)
  }
  return v
}

function cdBaseName (name) {
  // 同时处理 / 与 \（Windows），取最后一段。
  let n = name
  let slash = -1
  for (let i = 0; i < n.length; i++) {
    if (n.charAt(i) === '/' || n.charAt(i) === '\\') slash = i
  }
  if (slash >= 0) n = n.slice(slash + 1)
  return n
}

function cdIsDriveAbsolute (name) {
  // 形如 C:\ 或 C:/
  if (name.length < 3) return false
  const c0 = name.charCodeAt(0)
  const isLetter = (c0 >= 65 && c0 <= 90) || (c0 >= 97 && c0 <= 122)
  return isLetter && name.charAt(1) === ':' &&
    (name.charAt(2) === '\\' || name.charAt(2) === '/')
}

function cdExt (name) {
  const dot = name.lastIndexOf('.')
  return dot < 0 ? '' : name.slice(dot).toLowerCase()
}

class ContentDispositionGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultCdPolicy(), policy || {})
  }

  // 也可直接传单文件名（attachment 语义）评估。
  evaluate (headerOrName) {
    const pol = this.policy
    const findings = []
    const raw = String(headerOrName == null ? '' : headerOrName)
    if (raw.trim() === '') {
      findings.push({ reason: CD_REASON.EMPTY })
      return { safe: false, findings }
    }
    const hasSemicolon = raw.indexOf(';') >= 0
    const parsed = hasSemicolon
      ? cdParse(raw)
      : { type: 'attachment', filename: raw.trim(), filenameStar: null }

    if (pol.rejectControlChars && cdHasControlChar(raw)) {
      // CR/LF 单独强调，仍归到注入；同时加通用控制字符。
      if (raw.indexOf('\r') >= 0 || raw.indexOf('\n') >= 0) {
        findings.push({ reason: CD_REASON.CRLF_INJECTION })
      } else {
        findings.push({ reason: CD_REASON.CONTROL_CHAR })
      }
    }
    if (parsed.type && !pol.allowedTypes[parsed.type]) {
      findings.push({ reason: CD_REASON.UNKNOWN_TYPE, type: parsed.type })
    }
    const name = parsed.filename
    if (name !== null) {
      if (name.indexOf('..') >= 0 && (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0)) {
        findings.push({ reason: CD_REASON.PATH_TRAVERSAL, filename: name })
      }
      if (cdIsDriveAbsolute(name)) {
        findings.push({ reason: CD_REASON.ABSOLUTE_PATH, filename: name })
      }
      if (name.indexOf('\\\\') === 0) {
        findings.push({ reason: CD_REASON.UNC_PATH, filename: name })
      }
      if (pol.rejectExecutable) {
        const base = cdBaseName(name)
        const ext = cdExt(base)
        if (CD_EXEC_EXT[ext]) findings.push({ reason: CD_REASON.EXECUTABLE_EXTENSION, extension: ext })
      }
    }
    if (parsed.filenameStar !== null && name !== null) {
      const a = cdBaseName(name).toLowerCase()
      const star = parsed.filenameStar
      const q = star.indexOf("'")
      const starName = q >= 0 ? star.slice(star.lastIndexOf("'") + 1) : star
      if (cdBaseName(decodeURIComponentSafe(starName)).toLowerCase() !== a) {
        findings.push({ reason: CD_REASON.FILENAME_MISMATCH })
      }
    }
    return {
      safe: findings.length === 0,
      type: parsed.type,
      filename: name,
      filenameStar: parsed.filenameStar,
      findings: findings
    }
  }
}

function decodeURIComponentSafe (s) {
  try { return decodeURIComponent(s) } catch (e) { return s }
}

module.exports = Object.freeze({
  CD_REASON: CD_REASON,
  CD_EXEC_EXT: CD_EXEC_EXT,
  defaultCdPolicy: defaultCdPolicy,
  cdParse: cdParse,
  cdBaseName: cdBaseName,
  ContentDispositionGuard: ContentDispositionGuard
})
