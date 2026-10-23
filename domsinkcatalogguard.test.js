'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DSKGuard, DSK_REASON, DSK_BLOCK, DSK_WARN, DSK_ALLOW } = require('./domsinkcatalogguard.js')

test('DSK blocked tokens flagged', () => {
  const g = new DSKGuard()
  for (const tok of DSK_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === DSK_REASON.BLOCK), tok)
  }
})

test('DSK warn tokens flagged', () => {
  const g = new DSKGuard()
  for (const tok of DSK_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === DSK_REASON.WARN), tok)
  }
})

test('DSK allow tokens safe', () => {
  const g = new DSKGuard()
  for (const tok of DSK_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('DSK empty unsafe', () => {
  const r = new DSKGuard().audit('')
  assert.equal(r.safe, false)
})
