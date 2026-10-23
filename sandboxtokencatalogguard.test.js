'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SBTGuard, SBT_REASON, SBT_BLOCK, SBT_WARN, SBT_ALLOW } = require('./sandboxtokencatalogguard.js')

test('SBT blocked tokens flagged', () => {
  const g = new SBTGuard()
  for (const tok of SBT_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === SBT_REASON.BLOCK), tok)
  }
})

test('SBT warn tokens flagged', () => {
  const g = new SBTGuard()
  for (const tok of SBT_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === SBT_REASON.WARN), tok)
  }
})

test('SBT allow tokens safe', () => {
  const g = new SBTGuard()
  for (const tok of SBT_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('SBT empty unsafe', () => {
  const r = new SBTGuard().audit('')
  assert.equal(r.safe, false)
})
