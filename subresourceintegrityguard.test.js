'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SubresourceIntegrityGuard, parseIntegrity, SRI_REASON } = require('./subresourceintegrityguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const SHA = 'sha384-' + 'A'.repeat(64)

test('cross-origin script with strong integrity + crossorigin safe', () => {
  const g = new SubresourceIntegrityGuard()
  const r = g.evaluate({ tag: 'script', url: 'https://cdn.test/a.js', integrity: SHA, crossOrigin: 'anonymous', baseOrigin: 'https://app.test' })
  assert.equal(r.safe, true, JSON.stringify(r.findings))
})

test('cross-origin script without integrity flagged', () => {
  const g = new SubresourceIntegrityGuard()
  const r = g.evaluate({ tag: 'script', url: 'https://cdn.test/a.js', baseOrigin: 'https://app.test' })
  assert.ok(reasonsOf(r).includes(SRI_REASON.MISSING_INTEGRITY))
})

test('sha1 weak algorithm flagged', () => {
  const g = new SubresourceIntegrityGuard()
  const r = g.evaluate({ tag: 'script', url: 'https://cdn.test/a.js', integrity: 'sha1-' + 'a'.repeat(28), crossOrigin: 'anonymous', baseOrigin: 'https://app.test' })
  assert.ok(reasonsOf(r).includes(SRI_REASON.WEAK_ALGORITHM))
})

test('integrity without crossorigin flagged', () => {
  const g = new SubresourceIntegrityGuard()
  const r = g.evaluate({ tag: 'script', url: 'https://cdn.test/a.js', integrity: SHA, baseOrigin: 'https://app.test' })
  assert.ok(reasonsOf(r).includes(SRI_REASON.MISSING_CROSSORIGIN))
})

test('empty hash flagged', () => {
  const g = new SubresourceIntegrityGuard()
  const r = g.evaluate({ tag: 'script', url: 'https://cdn.test/a.js', integrity: 'sha384-', crossOrigin: 'anonymous', baseOrigin: 'https://app.test' })
  assert.ok(reasonsOf(r).includes(SRI_REASON.EMPTY_HASH))
})

test('data uri exempt', () => {
  const g = new SubresourceIntegrityGuard()
  assert.equal(g.evaluate({ tag: 'script', url: 'data:text/javascript,1', baseOrigin: 'https://app.test' }).safe, true)
})

test('same-origin not required by default', () => {
  const g = new SubresourceIntegrityGuard()
  assert.equal(g.evaluate({ tag: 'script', url: 'https://app.test/a.js', baseOrigin: 'https://app.test' }).safe, true)
})

test('same-origin required by policy', () => {
  const g = new SubresourceIntegrityGuard({ requireForSameOrigin: true })
  assert.ok(reasonsOf(g.evaluate({ tag: 'script', url: 'https://app.test/a.js', baseOrigin: 'https://app.test' })).includes(SRI_REASON.MISSING_INTEGRITY))
})

test('non script/link not applicable', () => {
  const g = new SubresourceIntegrityGuard()
  assert.equal(g.evaluate({ tag: 'img', url: 'https://x.test/a.png' }).safe, true)
})

test('parse multiple hashes', () => {
  const p = parseIntegrity('sha256-' + 'b'.repeat(43) + ' sha384-' + 'c'.repeat(64))
  assert.equal(p.entries.length, 2)
})

test('malformed token', () => {
  const p = parseIntegrity('garbage')
  assert.equal(p.malformed.length, 1)
})
