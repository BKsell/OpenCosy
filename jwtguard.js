'use strict'

// jwtguard.js —— JWT 头/载荷的安全解析与算法混淆守卫（不做签名验证，只审计结构）。
//
// 威胁模型：
//   浏览器内置登录会拿到 ID token / access token。错误处理常见漏洞：
//     - alg:none 被当成已签名 token 接受；
//     - RS256/ES256 公钥被拿去校验 HS256（算法混淆），用公钥当 HMAC 密钥即可伪造；
//     - 用 "kid"、"jku"、"x5u" 指定远端密钥 URL（SSRF / 投毒）；
//     - 缺少 exp、exp 已过期、exp 距离签发过远；iat 在未来；
//     - 段数不为 3、base64url 非法、解析出非对象。
//   本模块仅审计 token 结构与声明，不负责验签。纯字符 base64url 解码，不使用正则。

const JWT_REASON = Object.freeze({
  BAD_SEGMENTS: 'jwt-does-not-have-three-segments',
  BAD_BASE64URL: 'jwt-segment-not-valid-base64url',
  NOT_OBJECT: 'jwt-header-or-payload-not-json-object',
  ALG_NONE: 'jwt-alg-is-none',
  ALG_MISSING: 'jwt-header-missing-alg',
  ALG_UNKNOWN: 'jwt-algorithm-not-in-allowlist',
  KEY_REFERENCE_URL: 'jwt-header-carries-remote-key-reference',
  EXP_MISSING: 'jwt-missing-exp',
  EXP_EXPIRED: 'jwt-exp-in-the-past',
  EXP_TOO_FAR: 'jwt-lifetime-exceeds-max',
  IAT_IN_FUTURE: 'jwt-iat-in-the-future'
})

const ASYMMETRIC = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'EdDSA']
const SYMMETRIC = ['HS256', 'HS384', 'HS512']

function b64urlDecode (seg) {
  const okChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  for (let i = 0; i < seg.length; i++) {
    if (okChars.indexOf(seg[i]) < 0) return null
  }
  let s = ''
  for (let i = 0; i < seg.length; i++) {
    if (seg[i] === '-') s += '+'
    else if (seg[i] === '_') s += '/'
    else s += seg[i]
  }
  while (s.length % 4 !== 0) s += '='
  try {
    if (typeof atob === 'function') return atob(s)
    return Buffer.from(s, 'base64').toString('binary')
  } catch (e) {
    return null
  }
}

function jwtParseJson (seg) {
  const bin = b64urlDecode(seg)
  if (bin === null) return { error: JWT_REASON.BAD_BASE64URL }
  try {
    const obj = JSON.parse(bin)
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return { error: JWT_REASON.NOT_OBJECT }
    }
    return { value: obj }
  } catch (e) {
    return { error: JWT_REASON.NOT_OBJECT }
  }
}

class JwtGuard {
  // opts: { now: unix秒, maxLifetime: 秒, allowAsymmetricOnly: bool }
  constructor (opts) {
    const o = opts || {}
    this.now = typeof o.now === 'number' ? o.now : Math.floor(Date.now() / 1000)
    this.maxLifetime = typeof o.maxLifetime === 'number' ? o.maxLifetime : 60 * 60 * 24
  }

  inspect (token) {
    const findings = []
    const parts = String(token).split('.')
    if (parts.length !== 3) return { safe: false, findings: [{ reason: JWT_REASON.BAD_SEGMENTS }] }

    const hdr = jwtParseJson(parts[0])
    const pld = jwtParseJson(parts[1])
    if (hdr.error) findings.push({ reason: hdr.error })
    if (pld.error) findings.push({ reason: pld.error })
    const header = hdr.value || {}
    const payload = pld.value || {}

    const alg = typeof header.alg === 'string' ? header.alg : ''
    if (!('alg' in header)) findings.push({ reason: JWT_REASON.ALG_MISSING })
    if (alg.toLowerCase() === 'none') findings.push({ reason: JWT_REASON.ALG_NONE })
    if (alg && alg.toLowerCase() !== 'none' &&
        ASYMMETRIC.indexOf(alg) < 0 && SYMMETRIC.indexOf(alg) < 0) {
      findings.push({ reason: JWT_REASON.ALG_UNKNOWN, detail: alg })
    }
    for (const ref of ['jku', 'x5u', 'kid']) {
      if (ref === 'kid') continue
      if (typeof header[ref] === 'string' && header[ref] !== '') {
        findings.push({ reason: JWT_REASON.KEY_REFERENCE_URL, detail: ref })
      }
    }

    if (typeof payload.exp !== 'number') {
      findings.push({ reason: JWT_REASON.EXP_MISSING })
    } else {
      if (payload.exp <= this.now) findings.push({ reason: JWT_REASON.EXP_EXPIRED })
      const base = typeof payload.iat === 'number' ? payload.iat : this.now
      if (payload.exp - base > this.maxLifetime) findings.push({ reason: JWT_REASON.EXP_TOO_FAR })
    }
    if (typeof payload.iat === 'number' && payload.iat > this.now + 60) {
      findings.push({ reason: JWT_REASON.IAT_IN_FUTURE })
    }
    return { safe: findings.length === 0, findings: findings, header: header, payload: payload }
  }

  // 判定期望非对称算法却收到对称算法（算法混淆信号）。
  isAlgorithmConfusion (expectedFamily, header) {
    const alg = header && header.alg
    if (expectedFamily === 'asymmetric' && SYMMETRIC.indexOf(alg) >= 0) return true
    if (expectedFamily === 'symmetric' && ASYMMETRIC.indexOf(alg) >= 0) return true
    return false
  }
}

module.exports = Object.freeze({
  JWT_REASON: JWT_REASON,
  ASYMMETRIC: ASYMMETRIC,
  SYMMETRIC: SYMMETRIC,
  JwtGuard: JwtGuard
})
