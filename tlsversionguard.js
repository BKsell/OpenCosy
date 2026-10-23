'use strict'

// tlsversionguard.js —— TLS 协议版本与弱密码套件/证书签名守卫。
//
// 威胁模型：
//   浏览器对老旧站点降级到 TLS 1.0/1.1 或允许弱密码套件（RC4、3DES、EXPORT、匿名 DH），
//   会被 BEAST/POODLE/SWEET32/Logjam 等攻击破解；证书用 SHA-1/MD5 签名也可被伪造。
//   本模块审计一次连接协商结果：协议版本、密码套件名、证书签名算法、密钥强度。
//   纯字符匹配，不使用正则。

const TLS_REASON = Object.freeze({
  PROTOCOL_TOO_OLD: 'tls-protocol-version-below-1-2',
  PROTOCOL_UNKNOWN: 'tls-protocol-version-unrecognized',
  WEAK_CIPHER: 'tls-cipher-suite-is-weak-or-export-grade',
  WEAK_SIGNATURE: 'tls-certificate-signed-with-sha1-or-md5',
  WEAK_KEY: 'tls-certificate-public-key-too-short',
  FORWARD_SECRECY_MISSING: 'tls-cipher-suite-lacks-forward-secrecy'
})

const MIN_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']
const WEAK_CIPHER_TOKENS = ['RC4', '3DES', 'DES', 'EXPORT', 'NULL', 'ANON', 'MD5']
const FORWARD_SECRET_TOKENS = ['DHE', 'ECDHE']

function tlsUpper (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 97 && c <= 122 ? String.fromCharCode(c - 32) : s[i]
  }
  return out
}

function tlsContains (upper, token) {
  return upper.indexOf(token) >= 0
}

class TlsVersionGuard {
  // conn: { protocol, cipher, certSignature, certKeyBits }
  evaluate (conn) {
    const c = conn || {}
    const findings = []
    const proto = String(c.protocol || '')
    if (MIN_PROTOCOLS.indexOf(proto) < 0) {
      if (proto.indexOf('TLS') === 0 || proto.indexOf('SSL') === 0) {
        findings.push({ reason: TLS_REASON.PROTOCOL_TOO_OLD, detail: proto })
      } else {
        findings.push({ reason: TLS_REASON.PROTOCOL_UNKNOWN, detail: proto })
      }
    }
    const cipher = tlsUpper(String(c.cipher || ''))
    for (const tok of WEAK_CIPHER_TOKENS) {
      if (tlsContains(cipher, tok)) { findings.push({ reason: TLS_REASON.WEAK_CIPHER, detail: tok }); break }
    }
    let hasFS = false
    for (const tok of FORWARD_SECRET_TOKENS) {
      if (tlsContains(cipher, tok)) { hasFS = true; break }
    }
    // TLS 1.3 的所有套件都强制 (EC)DHE 前向保密，套件名里不再出现 ECDHE。
    if (cipher && !hasFS && proto !== 'TLSv1.3') {
      findings.push({ reason: TLS_REASON.FORWARD_SECRECY_MISSING })
    }

    const sig = tlsUpper(String(c.certSignature || ''))
    if (tlsContains(sig, 'SHA1') || tlsContains(sig, 'SHA-1') ||
        tlsContains(sig, 'MD5') || tlsContains(sig, 'MD2')) {
      findings.push({ reason: TLS_REASON.WEAK_SIGNATURE })
    }
    const bits = Number(c.certKeyBits)
    if (Number.isFinite(bits) && bits > 0 && bits < 2048) {
      findings.push({ reason: TLS_REASON.WEAK_KEY, detail: String(bits) })
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  TLS_REASON: TLS_REASON,
  TlsVersionGuard: TlsVersionGuard
})
