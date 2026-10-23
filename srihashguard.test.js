'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SriHashGuard, SRI_REASON, sriParse } = require('./srihashguard.js')

const SHA384 = 'sha384-' + 'A'.repeat(64)
const SHA256 = 'sha256-' + 'B'.repeat(44)
const SHA1 = 'sha1-' + 'C'.repeat(28)

function reasons (i) {
  return new SriHashGuard().evaluate(i).findings.map((f) => f.reason)
}

test('parse descriptors', () => {
  const p = sriParse(SHA384 + ' ' + SHA256)
  assert.equal(p.parsed.length, 2)
  assert.equal(p.parsed[0].alg, 'sha384')
})

test('cross-origin without integrity flagged', () => {
  assert.ok(reasons({ crossOrigin: true }).includes(SRI_REASON.MISSING_INTEGRITY))
})

test('same-origin without integrity allowed', () => {
  assert.equal(new SriHashGuard().evaluate({ crossOrigin: false }).safe, true)
})

test('strong integrity with crossorigin safe', () => {
  const r = new SriHashGuard().evaluate({
    crossOrigin: true, integrity: SHA384, crossorigin: 'anonymous'
  })
  assert.equal(r.safe, true)
})

test('strong integrity without crossorigin flagged', () => {
  assert.ok(reasons({ crossOrigin: true, integrity: SHA384 }).includes(SRI_REASON.MISSING_CROSSORIGIN))
})

test('sha1 only flagged weak', () => {
  assert.ok(reasons({ crossOrigin: true, integrity: SHA1, crossorigin: 'anonymous' }).includes(SRI_REASON.WEAK_ALGORITHM))
})

test('malformed descriptor flagged', () => {
  assert.ok(reasons({ crossOrigin: true, integrity: 'sha384-not base64!!', crossorigin: 'a' }).includes(SRI_REASON.MALFORMED))
})

test('digest match passes', () => {
  const r = new SriHashGuard().evaluate({
    crossOrigin: true, integrity: SHA256, crossorigin: 'a', actualDigest: SHA256
  })
  assert.equal(r.safe, true)
})

test('digest mismatch flagged', () => {
  const r = reasons({
    crossOrigin: true, integrity: SHA256, crossorigin: 'a', actualDigest: SHA384
  })
  assert.ok(r.includes(SRI_REASON.HASH_MISMATCH))
})
