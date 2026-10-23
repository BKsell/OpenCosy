'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ResourceHintsGuard, rhOriginOf, RH_REASON } = require('./resourcehintsguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const PAGE = 'https://app.test/'

test('same-page preconnect https safe', () => {
  const g = new ResourceHintsGuard()
  assert.equal(g.evaluate([{ rel: 'preconnect', href: 'https://app.test/api' }], PAGE).safe, true)
})

test('allowlisted third party preconnect safe', () => {
  const g = new ResourceHintsGuard({ allowedOrigins: ['https://cdn.test'] })
  assert.equal(g.evaluate([{ rel: 'preconnect', href: 'https://cdn.test/lib' }], PAGE).safe, true)
})

test('http preconnect flagged', () => {
  const g = new ResourceHintsGuard()
  assert.ok(reasonsOf(g.evaluate([{ rel: 'preconnect', href: 'http://cdn.test' }], PAGE)).includes(RH_REASON.INSECURE_SCHEME))
})

test('prerender third party flagged and elevated', () => {
  const g = new ResourceHintsGuard()
  const r = g.evaluate([{ rel: 'prerender', href: 'https://tracker.test/x' }], PAGE)
  assert.ok(reasonsOf(r).includes(RH_REASON.PRERENDER_RISK))
})

test('plain third-party preconnect allowed by default', () => {
  const g = new ResourceHintsGuard()
  assert.equal(g.evaluate([{ rel: 'dns-prefetch', href: 'https://fonts.test' }], PAGE).safe, true)
})

test('plain third-party preconnect rejected when strict', () => {
  const g = new ResourceHintsGuard({ rejectThirdParty: true })
  assert.ok(reasonsOf(g.evaluate([{ rel: 'preconnect', href: 'https://fonts.test' }], PAGE)).includes(RH_REASON.THIRD_PARTY_ORIGIN))
})

test('unknown rel flagged', () => {
  const g = new ResourceHintsGuard()
  assert.ok(reasonsOf(g.evaluate([{ rel: 'stylesheet', href: 'https://x.test/a.css' }], PAGE)).includes(RH_REASON.UNKNOWN_REL))
})

test('malformed href flagged', () => {
  const g = new ResourceHintsGuard()
  assert.ok(reasonsOf(g.evaluate([{ rel: 'preconnect', href: 'not-a-url' }], PAGE)).includes(RH_REASON.MALFORMED_HREF))
})

test('count and origin parser', () => {
  const g = new ResourceHintsGuard()
  const r = g.evaluate([
    { rel: 'preconnect', href: 'https://a.test' },
    { rel: 'prefetch', href: 'https://b.test/x' }
  ], PAGE)
  assert.equal(r.count, 2)
  assert.equal(rhOriginOf('https://a.test:8443/x').key, 'https://a.test:8443')
})
