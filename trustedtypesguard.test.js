'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TrustedTypesGuard, ttParseCsp, TT_REASON } = require('./trustedtypesguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const CSP_GOOD = "default-src 'self'; require-trusted-types-for 'script'; trusted-types appPolicy"

test('enforced with named policy safe', () => {
  const g = new TrustedTypesGuard()
  const r = g.evaluate(CSP_GOOD)
  assert.equal(r.safe, true, JSON.stringify(r.findings))
  assert.equal(r.enforced, true)
})

test('missing require flagged', () => {
  const g = new TrustedTypesGuard()
  assert.ok(reasonsOf(g.evaluate("default-src 'self'")).includes(TT_REASON.REQUIRE_MISSING))
})

test('bad require value flagged', () => {
  const g = new TrustedTypesGuard()
  assert.ok(reasonsOf(g.evaluate("require-trusted-types-for 'none'")).includes(TT_REASON.REQUIRE_BAD_VALUE))
})

test('empty require value flagged', () => {
  const g = new TrustedTypesGuard()
  assert.ok(reasonsOf(g.evaluate('require-trusted-types-for')).includes(TT_REASON.REQUIRE_BAD_VALUE))
})

test('wildcard policy flagged', () => {
  const g = new TrustedTypesGuard()
  assert.ok(reasonsOf(g.evaluate("require-trusted-types-for 'script'; trusted-types *")).includes(TT_REASON.WILDCARD_POLICY))
})

test('allow-duplicates flagged when strict', () => {
  const g = new TrustedTypesGuard({ rejectAllowDuplicates: true })
  assert.ok(reasonsOf(g.evaluate("require-trusted-types-for 'script'; trusted-types p allow-duplicates")).includes(TT_REASON.ALLOW_DUPLICATES))
})

test('trusted-types with only keyword no name flagged', () => {
  const g = new TrustedTypesGuard()
  assert.ok(reasonsOf(g.evaluate("require-trusted-types-for 'script'; trusted-types default")).includes(TT_REASON.NO_POLICY_DECLARED))
})

test('control char flagged', () => {
  const g = new TrustedTypesGuard()
  assert.ok(reasonsOf(g.evaluate(CSP_GOOD + '\n')).includes(TT_REASON.CONTROL_CHAR))
})

test('parser counts directives', () => {
  const p = ttParseCsp(CSP_GOOD)
  assert.equal(p.requireCount, 1)
  assert.equal(p.policyCount, 1)
})
