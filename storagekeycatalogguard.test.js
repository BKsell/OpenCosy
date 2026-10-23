'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SKCGuard, SKC_REASON, SKC_BLOCK, SKC_WARN, SKC_ALLOW } = require('./storagekeycatalogguard.js')

test('SKC blocked tokens flagged', () => {
  const g = new SKCGuard()
  for (const tok of SKC_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === SKC_REASON.BLOCK), tok)
  }
})

test('SKC warn tokens flagged', () => {
  const g = new SKCGuard()
  for (const tok of SKC_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === SKC_REASON.WARN), tok)
  }
})

test('SKC allow tokens safe', () => {
  const g = new SKCGuard()
  for (const tok of SKC_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('SKC empty unsafe', () => {
  const r = new SKCGuard().audit('')
  assert.equal(r.safe, false)
})
