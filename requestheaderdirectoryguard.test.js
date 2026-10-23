'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { QHDGuard, QHD_REASON, QHD_BLOCK, QHD_WARN, QHD_ALLOW } = require('./requestheaderdirectoryguard.js')

test('QHD blocked tokens flagged', () => {
  const g = new QHDGuard()
  for (const tok of QHD_BLOCK) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === QHD_REASON.BLOCK), tok)
  }
})

test('QHD warn tokens flagged', () => {
  const g = new QHDGuard()
  for (const tok of QHD_WARN) {
    const r = g.audit(tok)
    assert.ok(r.findings.some((f) => f.reason === QHD_REASON.WARN), tok)
  }
})

test('QHD allow tokens safe', () => {
  const g = new QHDGuard()
  for (const tok of QHD_ALLOW) {
    const r = g.audit(tok)
    assert.equal(r.safe, true, tok + ' ' + JSON.stringify(r.findings))
  }
})

test('QHD empty unsafe', () => {
  const r = new QHDGuard().audit('')
  assert.equal(r.safe, false)
})
