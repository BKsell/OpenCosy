'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FICGuard, FIC_REASON, FIC_BLOCK, FIC_WARN, FIC_ALLOW } = require('./fetchinitcatalogguard.js')

test('FIC blocked tokens flagged', () => {
  const g = new FICGuard()
  for (const tok of FIC_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === FIC_REASON.BLOCK), tok)
  }
})

test('FIC warn tokens flagged', () => {
  const g = new FICGuard()
  for (const tok of FIC_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === FIC_REASON.WARN), tok)
  }
})

test('FIC allow tokens safe', () => {
  const g = new FICGuard()
  for (const tok of FIC_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('FIC empty unsafe', () => {
  const r = new FICGuard().audit('')
  assert.equal(r.safe, false)
})
