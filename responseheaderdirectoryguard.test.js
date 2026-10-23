'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { RHDGuard, RHD_REASON, RHD_BLOCK, RHD_WARN, RHD_ALLOW } = require('./responseheaderdirectoryguard.js')

test('RHD blocked tokens flagged', () => {
  const g = new RHDGuard()
  for (const tok of RHD_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === RHD_REASON.BLOCK), tok)
  }
})

test('RHD warn tokens flagged', () => {
  const g = new RHDGuard()
  for (const tok of RHD_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === RHD_REASON.WARN), tok)
  }
})

test('RHD allow tokens safe', () => {
  const g = new RHDGuard()
  for (const tok of RHD_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('RHD empty unsafe', () => {
  const r = new RHDGuard().audit('')
  assert.equal(r.safe, false)
})
