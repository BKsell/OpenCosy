'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ContentLengthGuard, CL2_REASON, clParse } = require('./contentlengthguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('parse valid and invalid', () => {
  assert.equal(clParse('123').value, 123)
  assert.equal(clParse('12a').ok, false)
  assert.equal(clParse('-1').ok, false)
  assert.equal(clParse('').ok, false)
})

test('exact body matches declared', () => {
  const g = new ContentLengthGuard()
  g.begin('10')
  g.account(4)
  g.account(6)
  assert.equal(g.finish(false).safe, true)
})

test('short body flagged', () => {
  const g = new ContentLengthGuard()
  g.begin('10')
  g.account(4)
  assert.ok(reasons(g.finish(false)).includes(CL2_REASON.SHORT_BODY))
})

test('truncated connection flagged', () => {
  const g = new ContentLengthGuard()
  g.begin('10')
  g.account(3)
  assert.ok(reasons(g.finish(true)).includes(CL2_REASON.SHORT_BODY))
})

test('extra bytes during read flagged immediately', () => {
  const g = new ContentLengthGuard()
  g.begin('5')
  g.account(5)
  assert.ok(reasons(g.account(1)).includes(CL2_REASON.EXTRA_BYTES))
})

test('over-limit declared length flagged', () => {
  const g = new ContentLengthGuard(100)
  assert.ok(reasons(g.begin('101')).includes(CL2_REASON.OVER_LIMIT))
})

test('bad format flagged', () => {
  const g = new ContentLengthGuard()
  assert.ok(reasons(g.begin('0x10')).includes(CL2_REASON.BAD_FORMAT))
})

test('missing length means no check', () => {
  const g = new ContentLengthGuard()
  assert.equal(g.begin('').safe, true)
  g.account(999)
  assert.equal(g.finish(false).safe, true)
})

test('unsafe precision length flagged', () => {
  const g = new ContentLengthGuard()
  assert.ok(reasons(g.begin('99999999999999999999')).includes(CL2_REASON.DECLARED_TOO_LARGE_FOR_PRECISION))
})
