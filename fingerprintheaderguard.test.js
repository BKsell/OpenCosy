'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { FingerprintHeaderGuard, fphContainsVersion, FPH_REASON } = require('./fingerprintheaderguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('x-powered-by flagged', () => {
  const g = new FingerprintHeaderGuard()
  assert.ok(reasonsOf(g.evaluate({ 'X-Powered-By': 'Express' })).includes(FPH_REASON.DISCLOSING_HEADER))
})

test('aspnet version flagged', () => {
  const g = new FingerprintHeaderGuard()
  assert.ok(reasonsOf(g.evaluate({ 'X-AspNet-Version': '4.0.30319' })).includes(FPH_REASON.DISCLOSING_HEADER))
})

test('server with version flagged', () => {
  const g = new FingerprintHeaderGuard()
  assert.ok(reasonsOf(g.evaluate({ Server: 'nginx/1.20.1' })).includes(FPH_REASON.VERSION_IN_VALUE))
})

test('server without version safe', () => {
  const g = new FingerprintHeaderGuard()
  assert.equal(g.evaluate({ Server: 'nginx' }).safe, true)
})

test('via internal hostname flagged', () => {
  const g = new FingerprintHeaderGuard()
  assert.ok(reasonsOf(g.evaluate({ Via: '1.1 proxy01.internal' })).includes(FPH_REASON.INTERNAL_HOSTNAME))
})

test('multiple header values', () => {
  const g = new FingerprintHeaderGuard()
  const r = g.evaluate({ 'X-Powered-By': ['PHP/7.4', 'ASP.NET'] })
  assert.equal(r.findings.length, 2)
})

test('clean headers safe', () => {
  const g = new FingerprintHeaderGuard()
  assert.equal(g.evaluate({ 'Content-Type': 'text/html' }).safe, true)
})

test('version detector', () => {
  assert.equal(fphContainsVersion('nginx/1.20'), true)
  assert.equal(fphContainsVersion('nginx'), false)
})
