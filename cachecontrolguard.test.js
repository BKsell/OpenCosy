'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CacheControlGuard, parseCacheControl, CC_REASON } = require('./cachecontrolguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('sensitive no-store safe', () => {
  const g = new CacheControlGuard()
  const r = g.evaluate('no-store, no-cache, must-revalidate', { sensitive: true })
  assert.equal(r.safe, true)
})

test('sensitive missing header flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate(null, { sensitive: true })).includes(CC_REASON.MISSING))
})

test('sensitive without no-store flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('private, max-age=0', { sensitive: true })).includes(CC_REASON.NO_STORE_MISSING))
})

test('public on sensitive flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('public, no-store', { sensitive: true })).includes(CC_REASON.PUBLIC_ON_SENSITIVE))
})

test('positive max-age on sensitive flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('no-store, max-age=600', { sensitive: true })).includes(CC_REASON.MAX_AGE_ON_SENSITIVE))
})

test('s-maxage on sensitive flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('no-store, s-maxage=600', { sensitive: true })).includes(CC_REASON.S_MAXAGE_ON_SENSITIVE))
})

test('immutable on sensitive flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('no-store, immutable', { sensitive: true })).includes(CC_REASON.IMMUTABLE_ON_SENSITIVE))
})

test('non-sensitive static asset allowed', () => {
  const g = new CacheControlGuard()
  const r = g.evaluate('public, max-age=31536000, immutable', { sensitive: false })
  assert.equal(r.safe, true)
})

test('non-sensitive default does not flag', () => {
  const g = new CacheControlGuard()
  assert.equal(g.evaluate('max-age=300').safe, true)
})

test('max age ceiling policy for non-sensitive', () => {
  const g = new CacheControlGuard({ enforceMaxAgeCeiling: true, maxAgeCeiling: 60 })
  assert.ok(reasonsOf(g.evaluate('max-age=300')).includes(CC_REASON.MAX_AGE_ON_SENSITIVE))
})

test('bad max-age value flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('max-age=soon', { sensitive: true })).includes(CC_REASON.BAD_MAX_AGE))
})

test('duplicate directive flagged', () => {
  const p = parseCacheControl('no-store, no-store')
  assert.ok(p.duplicates.includes('no-store'))
})

test('parse values and flags', () => {
  const p = parseCacheControl('no-store, max-age=0, private')
  assert.equal(p.flags['no-store'], true)
  assert.equal(p.flags['private'], true)
  assert.equal(p.values['max-age'], 0)
})

test('control char flagged', () => {
  const g = new CacheControlGuard()
  assert.ok(reasonsOf(g.evaluate('no-store\r\n', { sensitive: true })).includes(CC_REASON.CONTROL_CHAR))
})
