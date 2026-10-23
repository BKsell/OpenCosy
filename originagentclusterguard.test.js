'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OriginAgentClusterGuard, OAC_REASON } = require('./originagentclusterguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('?1 enabled safe', () => {
  const g = new OriginAgentClusterGuard()
  assert.equal(g.evaluate('?1').enabled, true)
  assert.equal(g.evaluate('?1').safe, true)
})

test('missing flagged', () => {
  const g = new OriginAgentClusterGuard()
  assert.ok(reasonsOf(g.evaluate(null)).includes(OAC_REASON.MISSING))
})

test('missing ok when not required', () => {
  const g = new OriginAgentClusterGuard({ required: false })
  assert.equal(g.evaluate(null).safe, true)
})

test('true is invalid (must be ?1)', () => {
  const g = new OriginAgentClusterGuard()
  assert.ok(reasonsOf(g.evaluate('true')).includes(OAC_REASON.INVALID))
})

test('?0 disabled', () => {
  const g = new OriginAgentClusterGuard()
  assert.ok(reasonsOf(g.evaluate('?0')).includes(OAC_REASON.DISABLED))
})

test('empty flagged', () => {
  const g = new OriginAgentClusterGuard()
  assert.ok(reasonsOf(g.evaluate(' ')).includes(OAC_REASON.EMPTY))
})

test('multiple comma flagged', () => {
  const g = new OriginAgentClusterGuard()
  assert.ok(reasonsOf(g.evaluate('?1, ?1')).includes(OAC_REASON.MULTIPLE))
})

test('control char flagged', () => {
  const g = new OriginAgentClusterGuard()
  assert.ok(reasonsOf(g.evaluate('?1\r')).includes(OAC_REASON.CONTROL_CHAR))
})
