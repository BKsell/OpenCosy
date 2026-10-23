'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { JSAGuard, JSA_REASON, JSA_BLOCK, JSA_WARN, JSA_ALLOW } = require('./jsapidangercatalogguard.js')

test('JSA blocked tokens flagged', () => {
  const g = new JSAGuard()
  for (const tok of JSA_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === JSA_REASON.BLOCK), tok)
  }
})

test('JSA warn tokens flagged', () => {
  const g = new JSAGuard()
  for (const tok of JSA_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === JSA_REASON.WARN), tok)
  }
})

test('JSA allow tokens safe', () => {
  const g = new JSAGuard()
  for (const tok of JSA_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('JSA empty unsafe', () => {
  const r = new JSAGuard().audit('')
  assert.equal(r.safe, false)
})
