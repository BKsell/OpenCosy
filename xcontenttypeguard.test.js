'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XContentTypeOptionsGuard, XCTO_REASON } = require('./xcontenttypeguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('exact nosniff safe', () => {
  const g = new XContentTypeOptionsGuard()
  const r = g.evaluate('nosniff')
  assert.equal(r.safe, true)
  assert.equal(r.nosniff, true)
})

test('uppercase nosniff accepted', () => {
  const g = new XContentTypeOptionsGuard()
  assert.equal(g.evaluate('NoSniff').safe, true)
})

test('trim whitespace', () => {
  const g = new XContentTypeOptionsGuard()
  assert.equal(g.evaluate('  nosniff  ').safe, true)
})

test('missing flagged', () => {
  const g = new XContentTypeOptionsGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(XCTO_REASON.MISSING))
})

test('empty flagged', () => {
  const g = new XContentTypeOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('')).includes(XCTO_REASON.EMPTY))
})

test('wrong value flagged', () => {
  const g = new XContentTypeOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('no-sniff')).includes(XCTO_REASON.NOT_NOSNIFF))
  assert.ok(reasonsOf(g.evaluate('nosniff, noopen')).includes(XCTO_REASON.NOT_NOSNIFF))
})

test('multiple comma values flagged', () => {
  const g = new XContentTypeOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('nosniff, nosniff')).includes(XCTO_REASON.MULTIPLE_VALUES))
})

test('control char flagged', () => {
  const g = new XContentTypeOptionsGuard()
  assert.ok(reasonsOf(g.evaluate('nosniff\r\n')).includes(XCTO_REASON.CONTROL_CHAR))
})

test('evaluateHeaders case-insensitive', () => {
  const g = new XContentTypeOptionsGuard()
  assert.equal(g.evaluateHeaders({ 'X-Content-Type-Options': 'nosniff' }).safe, true)
  assert.ok(reasonsOf(g.evaluateHeaders({})) .includes(XCTO_REASON.MISSING))
})
