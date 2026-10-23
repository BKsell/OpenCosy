'use strict'

// pkceguard.js —— OAuth PKCE（Proof Key for Code Exchange）的 verifier/challenge 守卫。
//
// 威胁模型：
//   桌面/浏览器登录走授权码 + PKCE，防止授权码被截获后换 token。薄弱实现：
//     - code_verifier 过短（<43 字符）或超长（>128）、字符集非法；
//     - 用 plain 方法（不做 S256，等于没有绑定）；
//     - challenge 与 verifier 不匹配；challenge 长度非法；
//     - 换 token 时没有回传 verifier。
//   本模块校验 verifier 强度、S256 派生并比对 challenge（通过注入的 sha256，便于在浏览器用
//   crypto.subtle / Node 用 crypto）。纯字符 base64url 校验，不使用正则。

const PK_REASON = Object.freeze({
  VERIFIER_TOO_SHORT: 'pkce-code-verifier-too-short',
  VERIFIER_TOO_LONG: 'pkce-code-verifier-too-long',
  VERIFIER_BAD_CHARS: 'pkce-code-verifier-illegal-character',
  METHOD_PLAIN: 'pkce-method-plain-not-s256',
  METHOD_UNSUPPORTED: 'pkce-method-unsupported',
  CHALLENGE_BAD_LEN: 'pkce-s256-challenge-bad-length',
  CHALLENGE_MISMATCH: 'pkce-challenge-does-not-match-verifier',
  VERIFIER_MISSING: 'pkce-code-verifier-missing-at-token-exchange'
})

const PK_ALLOWED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'

function pkAllAllowed (s) {
  for (let i = 0; i < s.length; i++) {
    if (PK_ALLOWED.indexOf(s[i]) < 0) return false
  }
  return true
}

// sha256Base64Url: async (verifier) => challenge
class PkceGuard {
  constructor (sha256Base64Url) {
    if (typeof sha256Base64Url !== 'function') {
      throw new Error('PkceGuard requires an injected sha256Base64Url function')
    }
    this.sha256 = sha256Base64Url
  }

  validateVerifier (verifier) {
    const findings = []
    const v = String(verifier || '')
    if (v.length === 0) findings.push({ reason: PK_REASON.VERIFIER_MISSING })
    if (v.length > 0 && v.length < 43) findings.push({ reason: PK_REASON.VERIFIER_TOO_SHORT })
    if (v.length > 128) findings.push({ reason: PK_REASON.VERIFIER_TOO_LONG })
    if (v.length > 0 && !pkAllAllowed(v)) findings.push({ reason: PK_REASON.VERIFIER_BAD_CHARS })
    return { safe: findings.length === 0, findings: findings }
  }

  validateMethod (method) {
    if (method === 'plain') return { safe: false, findings: [{ reason: PK_REASON.METHOD_PLAIN }] }
    if (method !== 'S256') return { safe: false, findings: [{ reason: PK_REASON.METHOD_UNSUPPORTED }] }
    return { safe: true, findings: [] }
  }

  // 异步：根据 verifier 派生 challenge 并比对。
  async verifyChallenge (verifier, challenge, method) {
    const methodCheck = this.validateMethod(method)
    if (!methodCheck.safe) return methodCheck
    const vCheck = this.validateVerifier(verifier)
    if (!vCheck.safe) return vCheck
    const expected = await this.sha256(verifier)
    if (String(challenge).length !== 43) {
      return { safe: false, findings: [{ reason: PK_REASON.CHALLENGE_BAD_LEN }] }
    }
    if (!pkAllAllowed(String(challenge))) {
      return { safe: false, findings: [{ reason: PK_REASON.VERIFIER_BAD_CHARS }] }
    }
    if (expected !== challenge) {
      return { safe: false, findings: [{ reason: PK_REASON.CHALLENGE_MISMATCH }] }
    }
    return { safe: true, findings: [] }
  }
}

module.exports = Object.freeze({
  PK_REASON: PK_REASON,
  PkceGuard: PkceGuard
})
