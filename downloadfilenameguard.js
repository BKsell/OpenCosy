'use strict'

// downloadfilenameguard.js —— 下载落盘文件名净化（路径穿越 / 保留名 / ADS / 控制字符）。
//
// 威胁模型：
//   Content-Disposition 的 filename、页面给 blob 的下载名都来自远端。恶意名可：
//     - 含 / 或 \ 或 .. 把文件写出下载目录（../../AppData/Roaming/.../startup）；
//     - Windows 保留名 CON/PRN/AUX/NUL/COM1/LPT1（大小写、带后缀都保留）；
//     - 尾部点/空格被 Win32 裁剪造成同名覆盖（a.txt. ）；
//     - 冒号产生 NTFS 备用数据流（a.txt:evil）；
//     - 控制字符/通配符 * ? " < > | 破坏路径。
//   本模块给出 sanitizeFilename：剥离目录段、替换非法字符、处理保留名与尾点空格。
//   纯字符处理，不使用正则。

const DF_REASON = Object.freeze({
  PATH_SEPARATOR: 'download-filename-contains-path-separator',
  PARENT_TRAVERSAL: 'download-filename-contains-parent-traversal',
  RESERVED_NAME: 'download-filename-is-windows-reserved-name',
  ADS_STREAM: 'download-filename-contains-ntfs-ads-colon',
  ILLEGAL_CHAR: 'download-filename-contains-illegal-char',
  CONTROL_CHAR: 'download-filename-contains-control-char',
  EMPTY_NAME: 'download-filename-empty-after-sanitize',
  TRAILING_DOT_SPACE: 'download-filename-ends-with-dot-or-space'
})

const ILLEGAL = new Set(['*', '?', '"', '<', '>', '|'])
const RESERVED = ['CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']

function dfUpper (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 97 && c <= 122 ? String.fromCharCode(c - 32) : s[i]
  }
  return out
}

function dfAudit (name) {
  const findings = []
  const s = String(name)
  if (s.indexOf('/') >= 0 || s.indexOf('\\') >= 0) findings.push({ reason: DF_REASON.PATH_SEPARATOR })
  if (s.indexOf('..') >= 0) findings.push({ reason: DF_REASON.PARENT_TRAVERSAL })
  if (s.indexOf(':') >= 0) findings.push({ reason: DF_REASON.ADS_STREAM })
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x20 || c === 0x7F) {
      findings.push({ reason: DF_REASON.CONTROL_CHAR })
      break
    }
  }
  for (let i = 0; i < s.length; i++) {
    if (ILLEGAL.has(s[i])) {
      findings.push({ reason: DF_REASON.ILLEGAL_CHAR })
      break
    }
  }
  if (s.length > 0 && (s[s.length - 1] === '.' || s[s.length - 1] === ' ')) {
    findings.push({ reason: DF_REASON.TRAILING_DOT_SPACE })
  }
  const stem = dfUpper(s.split('.')[0])
  if (RESERVED.indexOf(stem) >= 0) findings.push({ reason: DF_REASON.RESERVED_NAME })
  return findings
}

// 返回 { name, findings }：name 为可安全用于"单层落盘"的文件名。
function sanitizeFilename (rawName) {
  let s = String(rawName)
  // 只保留最后一段（去掉任何目录成分）
  let slash = -1
  for (let i = s.length - 1; i >= 0; i--) {
    if (s[i] === '/' || s[i] === '\\') { slash = i; break }
  }
  if (slash >= 0) s = s.slice(slash + 1)

  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    const ch = s[i]
    if (c < 0x20 || c === 0x7F) { out += '_'; continue }
    if (ch === ':' || ILLEGAL.has(ch)) { out += '_'; continue }
    out += ch
  }
  // 去掉尾部点/空格
  while (out.length > 0 && (out[out.length - 1] === '.' || out[out.length - 1] === ' ')) {
    out = out.slice(0, -1)
  }
  const findings = dfAudit(rawName)
  if (out.length === 0) findings.push({ reason: DF_REASON.EMPTY_NAME })
  const stem = dfUpper(out.split('.')[0])
  if (RESERVED.indexOf(stem) >= 0) out = '_' + out
  if (out.length === 0) out = 'download'
  return { name: out, findings: findings }
}

class DownloadFilenameGuard {
  audit (name) {
    const findings = dfAudit(name)
    return { safe: findings.length === 0, findings: findings }
  }

  sanitize (name) {
    return sanitizeFilename(name)
  }
}

module.exports = Object.freeze({
  DF_REASON: DF_REASON,
  sanitizeFilename: sanitizeFilename,
  DownloadFilenameGuard: DownloadFilenameGuard
})
