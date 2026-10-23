'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CrossOriginEmbedderPolicyGuard, COEP_REASON } = require('./coepguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('require-corp safe', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.equal(g.evaluate('require-corp').safe, true)
})

test('credentialless weak at strict floor', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('credentialless')).includes(COEP_REASON.WEAK))
})

test('credentialless ok at relaxed floor', () => {
  const g = new CrossOriginEmbedderPolicyGuard({ minLevel: 1 })
  assert.equal(g.evaluate('credentialless').safe, true)
})

test('unsafe-none flagged', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('unsafe-none')).includes(COEP_REASON.UNSAFE_NONE))
})

test('missing flagged', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(COEP_REASON.MISSING))
})

test('empty flagged', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.ok(reasonsOf(g.evaluate(' ')).includes(COEP_REASON.EMPTY))
})

test('invalid value', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.ok(reasonsOf(g.evaluate('isolate-me')).includes(COEP_REASON.INVALID))
})

test('report-only without enforce flagged', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  const r = g.evaluate(null, 'require-corp')
  assert.ok(reasonsOf(r).includes(COEP_REASON.REPORT_ONLY_WITHOUT_ENFORCE))
})

test('control char flagged', () => {
  const g = new CrossOriginEmbedderPolicyGuard()
  assert.ok(reasonsOf(g.evaluate("require-corp\n")).includes(COEP_REASON.CONTROL_CHAR))
})
