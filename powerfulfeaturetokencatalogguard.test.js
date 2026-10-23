'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PFTGuard, PFT_REASON, PFT_BLOCK, PFT_WARN, PFT_ALLOW } = require('./powerfulfeaturetokencatalogguard.js')

test('PFT blocked tokens flagged', () => {
  const g = new PFTGuard()
  for (const tok of PFT_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === PFT_REASON.BLOCK), tok)
  }
})

test('PFT warn tokens flagged', () => {
  const g = new PFTGuard()
  for (const tok of PFT_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === PFT_REASON.WARN), tok)
  }
})

test('PFT allow tokens safe', () => {
  const g = new PFTGuard()
  for (const tok of PFT_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('PFT empty unsafe', () => {
  const r = new PFTGuard().audit('')
  assert.equal(r.safe, false)
})
