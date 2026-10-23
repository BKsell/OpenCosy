'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ExpectCtGuard, ECT_REASON } = require('./expectctguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('absent is allowed (deprecated header)', () => {
  const g = new ExpectCtGuard()
  assert.equal(g.evaluate(null).safe, true)
})

test('enforce with max-age and https report safe', () => {
  const g = new ExpectCtGuard()
  const r = g.evaluate('max-age=86400, enforce, report-uri="https://r.test/c"')
  assert.equal(r.safe, true)
  assert.equal(r.enforce, true)
  assert.equal(r.maxAge, 86400)
})

test('max-age missing flagged', () => {
  const g = new ExpectCtGuard()
  assert.ok(reasonsOf(g.evaluate('enforce')).includes(ECT_REASON.MAX_AGE_MISSING))
})

test('max-age zero flagged', () => {
  const g = new ExpectCtGuard()
  assert.ok(reasonsOf(g.evaluate('max-age=0')).includes(ECT_REASON.MAX_AGE_ZERO))
})

test('bad max-age flagged', () => {
  const g = new ExpectCtGuard()
  assert.ok(reasonsOf(g.evaluate('max-age=soon')).includes(ECT_REASON.BAD_MAX_AGE))
})

test('insecure report-uri flagged', () => {
  const g = new ExpectCtGuard()
  const r = g.evaluate('max-age=86400, report-uri="http://r.test/c"')
  assert.ok(reasonsOf(r).includes(ECT_REASON.INSECURE_REPORT_URI))
})

test('duplicate max-age flagged', () => {
  const g = new ExpectCtGuard()
  assert.ok(reasonsOf(g.evaluate('max-age=1, max-age=2')).includes(ECT_REASON.DUPLICATE_MAX_AGE))
})

test('empty flagged', () => {
  const g = new ExpectCtGuard()
  assert.ok(reasonsOf(g.evaluate(' ')).includes(ECT_REASON.EMPTY))
})

test('control char flagged', () => {
  const g = new ExpectCtGuard()
  assert.ok(reasonsOf(g.evaluate('max-age=1\n')).includes(ECT_REASON.CONTROL_CHAR))
})
