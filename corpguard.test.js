'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CorpGuard, CORP_REASON } = require('./corpguard.js')

test('private resource without corp flagged', () => {
  assert.ok(new CorpGuard().evaluate({ resourceClass: 'private' }).findings.some((f) => f.reason === CORP_REASON.MISSING_ON_PRIVATE))
})

test('public resource without corp acceptable', () => {
  assert.equal(new CorpGuard().evaluate({ resourceClass: 'public' }).safe, true)
})

test('private same-origin safe', () => {
  assert.equal(new CorpGuard().evaluate({ resourceClass: 'private', header: 'same-origin' }).safe, true)
})

test('private cross-origin flagged', () => {
  const r = new CorpGuard().evaluate({ resourceClass: 'private', header: 'cross-origin' })
  assert.ok(r.findings.some((f) => f.reason === CORP_REASON.CROSS_ORIGIN_ON_PRIVATE))
})

test('strict isolation same-site flagged', () => {
  const r = new CorpGuard().evaluate({ resourceClass: 'private', header: 'same-site', strictIsolation: true })
  assert.ok(r.findings.some((f) => f.reason === CORP_REASON.SAME_SITE_ON_STRICT))
})

test('unknown corp value flagged', () => {
  const r = new CorpGuard().evaluate({ resourceClass: 'public', header: 'nope' })
  assert.ok(r.findings.some((f) => f.reason === CORP_REASON.UNKNOWN_VALUE))
})

test('public cross-origin acceptable', () => {
  assert.equal(new CorpGuard().evaluate({ resourceClass: 'public', header: 'cross-origin' }).safe, true)
})
