'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CoopPolicyGuard, COOP_REASON, COOP_MODE } = require('./cooppolicyguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('same-origin safe at strict default', () => {
  const g = new CoopPolicyGuard()
  const r = g.evaluate('same-origin')
  assert.equal(r.safe, true)
  assert.equal(r.level, 3)
})

test('unsafe-none flagged', () => {
  const g = new CoopPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('unsafe-none')).includes(COOP_REASON.UNSAFE_NONE))
})

test('allow-popups weak at strict default', () => {
  const g = new CoopPolicyGuard()
  const r = g.evaluate('same-origin-allow-popups')
  assert.ok(reasonsOf(r).includes(COOP_REASON.WEAK_ISOLATION))
})

test('noopener-allow-popups accepted at relaxed floor', () => {
  const g = new CoopPolicyGuard({ minLevel: 2 })
  assert.equal(g.evaluate('noopener-allow-popups').safe, true)
  assert.equal(g.evaluate('same-origin-allow-popups').safe, false)
})

test('missing flagged', () => {
  const g = new CoopPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(COOP_REASON.MISSING))
})

test('empty flagged', () => {
  const g = new CoopPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('  ')).includes(COOP_REASON.EMPTY))
})

test('invalid value', () => {
  const g = new CoopPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('isolate-everything')).includes(COOP_REASON.INVALID))
})

test('multiple comma flagged', () => {
  const g = new CoopPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('same-origin, unsafe-none')).includes(COOP_REASON.MULTIPLE))
})

test('control char flagged', () => {
  const g = new CoopPolicyGuard()
  assert.ok(reasonsOf(g.evaluate("same-origin\r")).includes(COOP_REASON.CONTROL_CHAR))
})

test('mode constant sanity', () => {
  assert.equal(COOP_MODE.SAME_ORIGIN, 'same-origin')
})
