'use strict'

// webcryptoalgorithmdirectoryguard.js —— WebCrypto 算法强度目录。
//
// 威胁模型：
//   MD5/SHA1/RSASSA-PKCS1-v1_5 弱哈希或需复核，SHA-256+/ECDSA/Ed25519/AES-GCM 等强算法放行。
//   纯字符查表，不用正则。

const WCA_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const WCA_BLOCK = Object.freeze([
  'MD5',
  'MD4',
  'MD2',
  'SHA-1',
  'SHA1',
  'SHA-0',
  'RIPEMD',
  'RIPEMD128',
  'RIPEMD160',
  'DES',
  '3DES',
  'DES-EDE',
  'DES-CBC',
  'RC2',
  'RC4',
  'RC4-40',
  'RC4-128',
  'EXPORT',
  'NULL',
  'anon',
  'ADH',
  'AECDH',
  'eNULL',
  'aNULL',
  'MD5-RSA',
  'SHA1-RSA',
  'RSASSA-PKCS1-v1_5-MD5',
  'RSASSA-PKCS1-v1_5-SHA1',
  'RSA-SHA1',
  'RSA-MD5',
  'HMAC-MD5',
  'HMAC-SHA1',
  'DH-DSS-SHA1',
  'DHE-DSS-SHA1',
  'ECDH-ECDSA-SHA1',
  'ECDH-RSA-SHA1',
  'ECDHE-ECDSA-SHA1',
  'ECDHE-RSA-SHA1',
])

const WCA_WARN = Object.freeze([
  'RSASSA-PKCS1-v1_5',
  'RSA-OAEP-SHA1',
  'RSA-PSS-SHA1',
  'HMAC',
  'PBKDF2',
  'PBKDF1',
  'ECDH',
  'DH',
  'DSA',
  'RSA-KEM',
  'RSAES-PKCS1-v1_5',
  'RSAES-OAEP',
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
  'A128KW',
  'A192KW',
  'A256KW',
  'A128GCMKW',
  'A192GCMKW',
  'A256GCMKW',
  'RSA1_5',
  'RSA-OAEP',
  'A128CBC',
  'A192CBC',
  'A256CBC',
  'A128CBC-HS256',
  'A192CBC-HS384',
  'A256CBC-HS512',
  'SHA256',
  'SHA384',
  'SHA512',
  'SHA-256',
  'SHA-384',
  'SHA-512',
  'ECDSA',
  'ECDSA-SHA256',
  'ECDSA-SHA384',
  'ECDSA-SHA512',
])

const WCA_ALLOW = Object.freeze([
  'SHA-512/224',
  'SHA-512/256',
  'SHA3-224',
  'SHA3-256',
  'SHA3-384',
  'SHA3-512',
  'SHAKE128',
  'SHAKE256',
  'BLAKE2',
  'BLAKE2b',
  'BLAKE2s',
  'HMAC-SHA256',
  'HMAC-SHA384',
  'HMAC-SHA512',
  'HKDF-SHA256',
  'HKDF-SHA384',
  'HKDF-SHA512',
  'RSASSA-PKCS1-v1_5-SHA256',
  'RSASSA-PKCS1-v1_5-SHA384',
  'RSASSA-PKCS1-v1_5-SHA512',
  'RSA-PSS',
  'RSA-OAEP-256',
  'RSA-OAEP-384',
  'RSA-OAEP-512',
  'RSA-PSS-SHA256',
  'RSA-PSS-SHA384',
  'RSA-PSS-SHA512',
  'Ed25519',
  'Ed448',
  'X25519',
  'X448',
  'AES-CTR',
  'AES-CBC',
  'AES-GCM',
  'AES-KW',
  'AES-128-GCM',
  'AES-192-GCM',
  'AES-256-GCM',
  'AES-128-CBC',
  'AES-192-CBC',
  'AES-256-CBC',
  'AES-128-CTR',
  'AES-192-CTR',
  'AES-256-CTR',
  'AES-128-KW',
  'AES-192-KW',
  'AES-256-KW',
  'CHACHA20-POLY1305',
  'CHACHA20-POLY1305-2',
  'XCHACHA20-POLY1305',
])

function WCALower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function WCAIn (list, v) {
  for (const x of list) { if (WCALower(x) === v) return true }
  return false
}

function WCAClassify (tok) {
  const v = WCALower(String(tok == null ? '' : tok).trim())
  if (WCAIn(WCA_BLOCK, v)) return WCA_CLASS.BLOCK
  if (WCAIn(WCA_WARN, v)) return WCA_CLASS.WARN
  if (WCAIn(WCA_ALLOW, v)) return WCA_CLASS.ALLOW
  return WCA_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  WCA_CLASS: WCA_CLASS,
  WCA_BLOCK: WCA_BLOCK,
  WCA_WARN: WCA_WARN,
  WCA_ALLOW: WCA_ALLOW,
  WCAClassify: WCAClassify
})
