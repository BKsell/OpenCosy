'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CorpPolicyGuard, CORP_REASON } = require('./corppolicyguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('same-origin safe', () => {
  const g = new CorpPolicyGuard()
  const r = g.evaluate('same-origin')
  assert.equal(r.safe, true)
  assert.equal(r.level, 2)
})

test('same-site below default', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('same-site')).includes(CORP_REASON.TOO_PERMISSIVE))
})

test('cross-origin too permissive for private data', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('cross-origin')).includes(CORP_REASON.TOO_PERMISSIVE))
})

test('policy can accept same-site floor', () => {
  const g = new CorpPolicyGuard({ minLevel: 1 })
  assert.equal(g.evaluate('same-site').safe, true)
  assert.equal(g.evaluate('cross-origin').safe, false)
})

test('missing flagged', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(CORP_REASON.MISSING))
})

test('empty flagged', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(' ')).includes(CORP_REASON.EMPTY))
})

test('invalid value', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('same')).includes(CORP_REASON.INVALID))
})

test('multiple comma flagged', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('same-origin, cross-origin')).includes(CORP_REASON.MULTIPLE))
})

test('control char flagged', () => {
  const g = new CorpPolicyGuard()
  assert.ok(reasonsOf(g.evaluate("same-origin\n")).includes(CORP_REASON.CONTROL_CHAR))
})
