'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const {
  HstsPolicyGuard,
  parseHsts,
  defaultHstsPolicy,
  HSTS_REASON
} = require('./hstspolicyguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('strong hsts with preload is safe over https', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=31536000; includeSubDomains; preload', { isSecureTransport: true })
  assert.equal(r.safe, true)
  assert.equal(r.maxAge, 31536000)
  assert.equal(r.flags.preload, true)
})

test('missing header fails', () => {
  const g = new HstsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null, { isSecureTransport: true })).includes(HSTS_REASON.MISSING))
  assert.ok(reasonsOf(g.evaluate(undefined, { isSecureTransport: true })).includes(HSTS_REASON.MISSING))
})

test('empty header fails', () => {
  const g = new HstsPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('   ', { isSecureTransport: true })).includes(HSTS_REASON.EMPTY))
})

test('max-age zero flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=0', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.MAX_AGE_ZERO))
})

test('short max-age flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=3600', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.MAX_AGE_TOO_SHORT))
})

test('missing max-age flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('includeSubDomains', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.MAX_AGE_MISSING))
})

test('non-numeric max-age malformed', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=abc', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.BAD_MAX_AGE))
})

test('duplicate max-age flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=10; max-age=31536000', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.DUPLICATE_MAX_AGE))
})

test('set over plain http flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=31536000', { isSecureTransport: false })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.INSECURE_TRANSPORT))
})

test('preload without includeSubDomains flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=31536000; preload', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.PRELOAD_WITHOUT_SUBDOMAINS))
})

test('control character flagged', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluate('max-age=31536000\nBad: 1', { isSecureTransport: true })
  assert.ok(reasonsOf(r).includes(HSTS_REASON.CONTROL_CHAR))
})

test('case-insensitive directive names', () => {
  const p = parseHsts('MAX-AGE=31536000; INCLUDESUBDOMAINS')
  assert.equal(p.maxAge, 31536000)
  assert.equal(p.flags.includesubdomains, true)
})

test('evaluateHeaders picks header case-insensitively', () => {
  const g = new HstsPolicyGuard()
  const r = g.evaluateHeaders({ 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' },
    { isSecureTransport: true })
  assert.equal(r.safe, true)
})

test('default policy exposes baseline', () => {
  const p = defaultHstsPolicy()
  assert.ok(p.minMaxAge >= 31536000)
})
