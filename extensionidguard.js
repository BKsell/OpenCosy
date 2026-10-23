'use strict'

// extensionidguard.js —— 浏览器扩展 ID 与更新来源校验守卫。
//
// 威胁模型：
//   浏览器支持加载/更新扩展。扩展 ID 与来源校验薄弱会导致装错或被替换：
//     - Chromium 风格 32 位 a-p 字母 ID 格式不对（含其它字符、长度不对）；
//     - 用 file:// 或任意 http(s) 地址作为 update_url，可下发恶意更新；
//     - update_url 主机不在允许清单；
//     - manifest 声明的 ID 与实际公钥派生 ID 不一致（manifest 伪造）。
//   本模块审计 ID 格式、update_url scheme/主机白名单、ID 一致性。纯字符判定，不使用正则。

const EI_REASON = Object.freeze({
  BAD_LENGTH: 'extension-id-length-not-32',
  BAD_CHARSET: 'extension-id-contains-character-outside-a-to-p',
  UPDATE_SCHEME: 'extension-update-url-not-https',
  UPDATE_HOST_NOT_ALLOWED: 'extension-update-host-not-in-allowlist',
  ID_MISMATCH: 'extension-manifest-id-does-not-match-derived-id'
})

const ID_CHARS = 'abcdefghijklmnop'

function eiLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 80 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

function eiValidId (id) {
  const s = String(id || '')
  if (s.length !== 32) return EI_REASON.BAD_LENGTH
  for (let i = 0; i < s.length; i++) {
    if (ID_CHARS.indexOf(s[i]) < 0) return EI_REASON.BAD_CHARSET
  }
  return null
}

function eiHost (url) {
  const s = String(url)
  const sep = s.indexOf('://')
  if (sep < 0) return { scheme: '', host: '' }
  const scheme = s.slice(0, sep).toLowerCase()
  let auth = s.slice(sep + 3)
  for (let i = 0; i < auth.length; i++) {
    if (auth[i] === '/' || auth[i] === '?' || auth[i] === '#') { auth = auth.slice(0, i); break }
  }
  const colon = auth.indexOf(':')
  if (colon >= 0) auth = auth.slice(0, colon)
  return { scheme: scheme, host: auth.toLowerCase() }
}

class ExtensionIdGuard {
  // allowedUpdateHosts: 主机白名单
  constructor (allowedUpdateHosts) {
    this.allow = new Set((allowedUpdateHosts || []).map((h) => String(h).toLowerCase()))
  }

  auditId (id) {
    const reason = eiValidId(eiLower(String(id || '')))
    return { safe: reason === null, findings: reason ? [{ reason: reason }] : [] }
  }

  auditUpdateUrl (url) {
    const findings = []
    const sh = eiHost(url)
    if (sh.scheme !== 'https') findings.push({ reason: EI_REASON.UPDATE_SCHEME, detail: sh.scheme })
    if (this.allow.size > 0 && !this.allow.has(sh.host)) {
      findings.push({ reason: EI_REASON.UPDATE_HOST_NOT_ALLOWED, detail: sh.host })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // manifestId 与公钥派生 ID 必须一致。
  auditIdMatch (manifestId, derivedId) {
    if (eiLower(String(manifestId)) !== eiLower(String(derivedId))) {
      return { safe: false, findings: [{ reason: EI_REASON.ID_MISMATCH }] }
    }
    return this.auditId(manifestId)
  }
}

module.exports = Object.freeze({
  EI_REASON: EI_REASON,
  eiValidId: eiValidId,
  ExtensionIdGuard: ExtensionIdGuard
})
