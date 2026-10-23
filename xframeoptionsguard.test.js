'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XFrameOptionsGuard, XFO_REASON, XFO_MODE } = require('./xframeoptionsguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('deny is safe', () => {
  const g = new XFrameOptionsGuard()
  const r = g.evaluate('DENY')
  assert.equal(r.safe, true)
  assert.equal(r.mode, XFO_MODE.DENY)
})

test('sameorigin is safe', () => {
  const g = new XFrameOptionsGuard()
  assert.equal(g.evaluate('SAMEORIGIN').safe, true)
})

test('lowercase accepted', () => {
  const g = new XFrameOptionsGuard()
  assert.equal(g.evaluate('sameorigin').mode, XFO_MODE.SAMEORIGIN)
})

test('missing flagged', () => {
  const g = new XFrameOptionsGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(XFO_REASON.MISSING))
})

test('empty flagged', () => {
  const g = new XFrameOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('  ')).includes(XFO_REASON.EMPTY))
})

test('allow-from deprecated', () => {
  const g = new XFrameOptionsGuard()
  const r = g.evaluate('ALLOW-FROM https://a.example')
  assert.ok(reasonsOf(r).includes(XFO_REASON.ALLOW_FROM_DEPRECATED))
  assert.equal(r.safe, false)
})

test('garbage value invalid', () => {
  const g = new XFrameOptionsGuard()
  const r = g.evaluate('yes-please-frame-me')
  assert.ok(reasonsOf(r).includes(XFO_REASON.INVALID_VALUE))
  assert.equal(r.safe, false)
})

test('comma multiple values flagged', () => {
  const g = new XFrameOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('DENY, SAMEORIGIN')).includes(XFO_REASON.MULTIPLE_VALUES))
})

test('control char flagged', () => {
  const g = new XFrameOptionsGuard()
  assert.ok(reasonsOf(g.evaluate("DENY\r\nX: y")).includes(XFO_REASON.CONTROL_CHAR))
})

test('duplicate headers conflict', () => {
  const g = new XFrameOptionsGuard()
  const r = g.evaluateMultiple(['DENY', 'SAMEORIGIN'])
  assert.ok(reasonsOf(r).includes(XFO_REASON.MULTIPLE_VALUES))
  assert.equal(r.safe, false)
})

test('duplicate headers single value ok', () => {
  const g = new XFrameOptionsGuard()
  assert.equal(g.evaluateMultiple(['SAMEORIGIN']).safe, true)
})

test('deny contradicting frame-ancestors flagged', () => {
  const g = new XFrameOptionsGuard()
  const r = g.evaluate('DENY', "'self'")
  assert.ok(reasonsOf(r).includes(XFO_REASON.CONTRADICTS_CSP))
})

test('deny consistent with frame-ancestors none', () => {
  const g = new XFrameOptionsGuard()
  assert.equal(g.evaluate('DENY', "'none'").safe, true)
})
