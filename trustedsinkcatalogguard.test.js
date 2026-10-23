'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { TSGGuard, TSG_REASON, TSG_BLOCK, TSG_WARN, TSG_ALLOW } = require('./trustedsinkcatalogguard.js')

test('TSG blocked tokens flagged', () => {
  const g = new TSGGuard()
  for (const tok of TSG_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === TSG_REASON.BLOCK), tok)
  }
})

test('TSG warn tokens flagged', () => {
  const g = new TSGGuard()
  for (const tok of TSG_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === TSG_REASON.WARN), tok)
  }
})

test('TSG allow tokens safe', () => {
  const g = new TSGGuard()
  for (const tok of TSG_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('TSG empty unsafe', () => {
  const r = new TSGGuard().audit('')
  assert.equal(r.safe, false)
})
