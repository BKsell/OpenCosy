'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ClearSiteDataGuard, CSD_REASON } = require('./clearsitedataguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('absent is safe', () => {
  assert.equal(new ClearSiteDataGuard().evaluate(null, true).safe, true)
})

test('quoted logout wildcard over https safe', () => {
  const g = new ClearSiteDataGuard()
  const r = g.evaluate('"*"', true)
  assert.equal(r.safe, true)
  assert.equal(r.wildcard, true)
})

test('unquoted directive flagged', () => {
  const g = new ClearSiteDataGuard()
  assert.ok(reasonsOf(g.evaluate('cache', true)).includes(CSD_REASON.UNQUOTED_DIRECTIVE))
})

test('quoted multiple directives safe', () => {
  const g = new ClearSiteDataGuard()
  assert.equal(g.evaluate('"cache", "cookies", "storage"', true).safe, true)
})

test('wildcard mixed with others flagged', () => {
  const g = new ClearSiteDataGuard()
  assert.ok(reasonsOf(g.evaluate('"*", "cache"', true)).includes(CSD_REASON.WILDCARD_MIXED))
})

test('insecure context flagged', () => {
  const g = new ClearSiteDataGuard()
  assert.ok(reasonsOf(g.evaluate('"*"', false)).includes(CSD_REASON.INSECURE_CONTEXT))
})

test('empty flagged', () => {
  const g = new ClearSiteDataGuard()
  assert.ok(reasonsOf(g.evaluate('  ', true)).includes(CSD_REASON.EMPTY))
})

test('unknown directive flagged', () => {
  const g = new ClearSiteDataGuard()
  assert.ok(reasonsOf(g.evaluate('"bogus"', true)).includes(CSD_REASON.UNKNOWN_DIRECTIVE))
})

test('control char flagged', () => {
  const g = new ClearSiteDataGuard()
  assert.ok(reasonsOf(g.evaluate('"cache"\n', true)).includes(CSD_REASON.CONTROL_CHAR))
})
