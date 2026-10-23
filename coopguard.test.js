'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CoopGuard, COOP_REASON } = require('./coopguard.js')

test('missing coop flagged', () => {
  assert.ok(new CoopGuard().evaluate({}).findings.some((f) => f.reason === COOP_REASON.MISSING))
})

test('same-origin on sensitive safe', () => {
  assert.equal(new CoopGuard().evaluate({ header: 'same-origin', sensitive: true }).safe, true)
})

test('unsafe-none on sensitive flagged', () => {
  const r = new CoopGuard().evaluate({ header: 'unsafe-none', sensitive: true })
  assert.ok(r.findings.some((f) => f.reason === COOP_REASON.UNSAFE_NONE))
})

test('allow-popups on sensitive flagged', () => {
  const r = new CoopGuard().evaluate({ header: 'same-origin-allow-popups', sensitive: true })
  assert.ok(r.findings.some((f) => f.reason === COOP_REASON.ALLOW_POPUPS_ON_SENSITIVE))
})

test('allow-popups on non-sensitive acceptable', () => {
  const r = new CoopGuard().evaluate({ header: 'same-origin-allow-popups', sensitive: false })
  assert.equal(r.safe, true)
})

test('unknown value flagged', () => {
  const r = new CoopGuard().evaluate({ header: 'weird' })
  assert.ok(r.findings.some((f) => f.reason === COOP_REASON.UNKNOWN_VALUE))
})

test('whitespace value normalized', () => {
  const r = new CoopGuard().evaluate({ header: '  same-origin  ', sensitive: true })
  assert.equal(r.value, 'same-origin')
})
