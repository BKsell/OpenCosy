'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TlsVersionGuard, TLS_REASON } = require('./tlsversionguard.js')

function reasons (c) {
  return new TlsVersionGuard().evaluate(c).findings.map((f) => f.reason)
}

test('modern tls1.2 ecdhe aesgcm safe', () => {
  const r = new TlsVersionGuard().evaluate({
    protocol: 'TLSv1.2',
    cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
    certSignature: 'SHA256withRSA',
    certKeyBits: 2048
  })
  assert.equal(r.safe, true)
})

test('tls1.3 suite safe despite no ECDHE in name', () => {
  const r = new TlsVersionGuard().evaluate({
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    certSignature: 'SHA256withRSA',
    certKeyBits: 2048
  })
  assert.equal(r.safe, true)
})

test('tls1.0 flagged', () => {
  assert.ok(reasons({ protocol: 'TLSv1.0', cipher: 'ECDHE-RSA-AES128-SHA' }).includes(TLS_REASON.PROTOCOL_TOO_OLD))
})

test('ssl3 flagged', () => {
  assert.ok(reasons({ protocol: 'SSLv3', cipher: 'RC4-MD5' }).includes(TLS_REASON.PROTOCOL_TOO_OLD))
})

test('rc4 cipher flagged', () => {
  assert.ok(reasons({ protocol: 'TLSv1.2', cipher: 'ECDHE-RSA-RC4-SHA' }).includes(TLS_REASON.WEAK_CIPHER))
})

test('export grade cipher flagged', () => {
  assert.ok(reasons({ protocol: 'TLSv1.2', cipher: 'DHE-RSA-DES-CBC3-SHA' }).includes(TLS_REASON.WEAK_CIPHER))
})

test('plain rsa key exchange lacks forward secrecy', () => {
  assert.ok(reasons({ protocol: 'TLSv1.2', cipher: 'AES128-GCM-SHA256' }).includes(TLS_REASON.FORWARD_SECRECY_MISSING))
})

test('sha1 cert signature flagged', () => {
  assert.ok(reasons({ protocol: 'TLSv1.2', cipher: 'ECDHE-RSA-AES128-GCM-SHA256', certSignature: 'SHA1withRSA' }).includes(TLS_REASON.WEAK_SIGNATURE))
})

test('short rsa key flagged', () => {
  assert.ok(reasons({ protocol: 'TLSv1.2', cipher: 'ECDHE-RSA-AES128-GCM-SHA256', certKeyBits: 1024 }).includes(TLS_REASON.WEAK_KEY))
})

test('unknown protocol flagged', () => {
  assert.ok(reasons({ protocol: 'weird', cipher: 'X' }).includes(TLS_REASON.PROTOCOL_UNKNOWN))
})
