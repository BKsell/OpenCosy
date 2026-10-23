'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XssProtectionGuard, XXP_REASON } = require('./xssprotectionguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('explicit zero is recommended and safe', () => {
  const g = new XssProtectionGuard()
  const r = g.evaluate('0')
  assert.equal(r.safe, true)
  assert.equal(r.explicitZero, true)
})

test('1 mode=block flagged', () => {
  const g = new XssProtectionGuard()
  assert.ok(reasonsOf(g.evaluate('1; mode=block')).includes(XXP_REASON.ENABLED_BLOCK))
})

test('1 report flagged', () => {
  const g = new XssProtectionGuard()
  assert.ok(reasonsOf(g.evaluate('1; report=https://r.test')).includes(XXP_REASON.ENABLED_REPORT))
})

test('plain 1 flagged', () => {
  const g = new XssProtectionGuard()
  assert.ok(reasonsOf(g.evaluate('1')).includes(XXP_REASON.ENABLED_PLAIN))
})

test('missing safe by default', () => {
  const g = new XssProtectionGuard()
  assert.equal(g.evaluate(null).safe, true)
})

test('missing fails under requireZero', () => {
  const g = new XssProtectionGuard({ requireZero: true })
  assert.ok(reasonsOf(g.evaluate(null)).includes(XXP_REASON.NOT_EXPLICIT_ZERO))
})

test('invalid value', () => {
  const g = new XssProtectionGuard()
  assert.ok(reasonsOf(g.evaluate('on')).includes(XXP_REASON.INVALID))
})

test('multiple comma flagged', () => {
  const g = new XssProtectionGuard()
  assert.ok(reasonsOf(g.evaluate('0, 1')).includes(XXP_REASON.MULTIPLE))
})

test('control char flagged', () => {
  const g = new XssProtectionGuard()
  assert.ok(reasonsOf(g.evaluate('0\n')).includes(XXP_REASON.CONTROL_CHAR))
})
