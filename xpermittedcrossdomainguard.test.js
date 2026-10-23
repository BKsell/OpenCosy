'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XPermittedCrossDomainGuard, XPCDP_REASON, XPCDP_MODE } = require('./xpermittedcrossdomainguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('none safe', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.equal(g.evaluate('none').safe, true)
})

test('all permissive', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate('all')).includes(XPCDP_REASON.PERMISSIVE))
})

test('master-only permissive', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate('master-only')).includes(XPCDP_REASON.PERMISSIVE))
})

test('missing flagged', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(XPCDP_REASON.MISSING))
})

test('missing ok when not required', () => {
  const g = new XPermittedCrossDomainGuard({ required: false })
  assert.equal(g.evaluate(null).safe, true)
})

test('empty flagged', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate(' ')).includes(XPCDP_REASON.EMPTY))
})

test('invalid value', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate('yes')).includes(XPCDP_REASON.INVALID))
})

test('multiple comma flagged', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate('none, all')).includes(XPCDP_REASON.MULTIPLE))
})

test('control char flagged', () => {
  const g = new XPermittedCrossDomainGuard()
  assert.ok(reasonsOf(g.evaluate('none\r')).includes(XPCDP_REASON.CONTROL_CHAR))
})

test('mode constant', () => {
  assert.equal(XPCDP_MODE.ALL, 'all')
})
