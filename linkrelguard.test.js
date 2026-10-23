'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { LinkRelGuard, lrOriginOf, LR_REASON } = require('./linkrelguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('cross-origin blank with noopener safe', () => {
  const g = new LinkRelGuard()
  const r = g.evaluate({ target: '_blank', rel: 'noopener', href: 'https://b.test/x', fromHref: 'https://a.test/' })
  assert.equal(r.safe, true)
})

test('noreferrer alone sufficient', () => {
  const g = new LinkRelGuard()
  const r = g.evaluate({ target: '_blank', rel: 'noreferrer', href: 'https://b.test/x', fromHref: 'https://a.test/' })
  assert.equal(r.safe, true)
})

test('cross-origin blank without rel flagged', () => {
  const g = new LinkRelGuard()
  const r = g.evaluate({ target: '_blank', href: 'https://b.test/x', fromHref: 'https://a.test/' })
  assert.ok(reasonsOf(r).includes(LR_REASON.MISSING_REL))
})

test('cross-origin blank with unrelated rel flagged', () => {
  const g = new LinkRelGuard()
  const r = g.evaluate({ target: '_blank', rel: 'stylesheet', href: 'https://b.test/x', fromHref: 'https://a.test/' })
  assert.ok(reasonsOf(r).includes(LR_REASON.TARGET_BLANK_NO_NOOPENER))
})

test('same-origin exempt by default', () => {
  const g = new LinkRelGuard()
  const r = g.evaluate({ target: '_blank', href: 'https://a.test/p', fromHref: 'https://a.test/' })
  assert.equal(r.safe, true)
})

test('same-origin not exempt when disabled', () => {
  const g = new LinkRelGuard({ sameOriginExempt: false })
  const r = g.evaluate({ target: '_blank', href: 'https://a.test/p', fromHref: 'https://a.test/' })
  assert.ok(reasonsOf(r).includes(LR_REASON.TARGET_BLANK_NO_NOOPENER))
})

test('non-blank target safe', () => {
  const g = new LinkRelGuard()
  assert.equal(g.evaluate({ target: '_self', href: 'https://b.test' }).safe, true)
})

test('force new window treated as blank', () => {
  const g = new LinkRelGuard()
  const r = g.evaluate({ forceNewWindow: true, href: 'https://b.test', fromHref: 'https://a.test' })
  assert.equal(r.opensNew, true)
  assert.ok(reasonsOf(r).length > 0)
})

test('origin extraction', () => {
  assert.equal(lrOriginOf('https://a.test:8443/x/y'), 'https://a.test:8443')
})
