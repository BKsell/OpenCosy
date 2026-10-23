'use strict'

// credentialstoreplaintextcatalogguard.js —— 凭据管理 API 风险目录。
//
// 威胁模型：
//   PasswordCredential 在 JS 内持有/存储明文口令属弱实践，未中介读取易被脚本取走，
//   应优先 WebAuthn/Passkey。纯字符查表，不用正则。

const CRA_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const CRA_BLOCK = Object.freeze([
  'passwordcredential',
  'store-plaintext',
  'get-without-mediation',
  'federatedcredential-untrusted',
])

const CRA_WARN = Object.freeze([
  'mediation-optional',
])

const CRA_ALLOW = Object.freeze([
  'publickeycredential',
  'passkey',
])

function CRALower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function CRAIn (list, v) {
  for (const x of list) { if (CRALower(x) === v) return true }
  return false
}

function CRAClassify (tok) {
  const v = CRALower(String(tok == null ? '' : tok).trim())
  if (CRAIn(CRA_BLOCK, v)) return CRA_CLASS.BLOCK
  if (CRAIn(CRA_WARN, v)) return CRA_CLASS.WARN
  if (CRAIn(CRA_ALLOW, v)) return CRA_CLASS.ALLOW
  return CRA_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  CRA_CLASS: CRA_CLASS,
  CRA_BLOCK: CRA_BLOCK,
  CRA_WARN: CRA_WARN,
  CRA_ALLOW: CRA_ALLOW,
  CRAClassify: CRAClassify
})
