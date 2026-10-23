'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DnsRebindGuard, DR_REASON } = require('./dnsrebindguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('all-public answer set passes', () => {
  const r = new DnsRebindGuard().evaluateAnswerSet([
    { ip: '52.84.1.9', ttl: 300 },
    { ip: '52.84.1.10', ttl: 300 }
  ])
  assert.equal(r.safe, true)
})

test('mixed scope answer set flagged', () => {
  const r = new DnsRebindGuard().evaluateAnswerSet([
    { ip: '52.84.1.9', ttl: 1 },
    { ip: '127.0.0.1', ttl: 1 }
  ])
  assert.ok(reasons(r).includes(DR_REASON.MIXED_SCOPE))
  assert.ok(reasons(r).includes(DR_REASON.INTERNAL_RECORD))
})

test('cloud metadata link-local flagged', () => {
  const r = new DnsRebindGuard().evaluateAnswerSet([{ ip: '169.254.169.254', ttl: 60 }])
  assert.ok(reasons(r).includes(DR_REASON.INTERNAL_RECORD))
})

test('private record flagged', () => {
  const r = new DnsRebindGuard().evaluateAnswerSet([{ ip: '10.0.0.5', ttl: 60 }])
  assert.ok(reasons(r).includes(DR_REASON.INTERNAL_RECORD))
})

test('zero ttl with mixed records flagged', () => {
  const r = new DnsRebindGuard().evaluateAnswerSet([
    { ip: '52.84.1.9', ttl: 0 },
    { ip: '192.168.0.1', ttl: 0 }
  ])
  assert.ok(reasons(r).includes(DR_REASON.SUSPICIOUS_TTL))
})

test('stable pin passes', () => {
  const g = new DnsRebindGuard()
  g.pin('cdn.example', '52.84.1.9')
  assert.equal(g.verifyConnect('cdn.example', '52.84.1.9').safe, true)
})

test('pin drift to loopback flagged', () => {
  const g = new DnsRebindGuard()
  g.pin('cdn.example', '52.84.1.9')
  const r = g.verifyConnect('cdn.example', '127.0.0.1')
  assert.equal(r.safe, false)
  assert.ok(reasons(r).includes(DR_REASON.PIN_DRIFT))
})

test('connect without prior pin flagged', () => {
  const r = new DnsRebindGuard().verifyConnect('unknown.example', '1.2.3.4')
  assert.equal(r.safe, false)
  assert.ok(reasons(r).includes(DR_REASON.PIN_DRIFT))
})
