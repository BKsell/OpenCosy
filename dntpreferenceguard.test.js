'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DntPreferenceGuard, DNT_REASON } = require('./dntpreferenceguard.js')

function reasons (s, r) {
  return new DntPreferenceGuard(s).evaluate(r).findings.map((f) => f.reason)
}

test('dnt enabled and header present safe', () => {
  const g = new DntPreferenceGuard({ dntEnabled: true })
  assert.equal(g.evaluate({ host: 'a.test', headers: { dnt: '1' } }).safe, true)
})

test('dnt enabled but missing flagged', () => {
  assert.ok(reasons({ dntEnabled: true }, { host: 'a.test', headers: {} }).includes(DNT_REASON.DNT_MISSING))
})

test('dnt wrong value flagged', () => {
  assert.ok(reasons({ dntEnabled: true }, { host: 'a.test', headers: { dnt: '0' } }).includes(DNT_REASON.WRONG_VALUE))
})

test('dnt disabled means nothing required', () => {
  const g = new DntPreferenceGuard({ dntEnabled: false })
  assert.equal(g.evaluate({ host: 'a.test', headers: {} }).safe, true)
})

test('gpc enabled requires sec-gpc', () => {
  assert.ok(reasons({ gpcEnabled: true }, { host: 'a.test', headers: {} }).includes(DNT_REASON.GPC_MISSING))
})

test('gpc header present safe', () => {
  const g = new DntPreferenceGuard({ gpcEnabled: true })
  assert.equal(g.evaluate({ host: 'a.test', headers: { 'sec-gpc': '1' } }).safe, true)
})

test('both enabled both headers checked', () => {
  const g = new DntPreferenceGuard({ dntEnabled: true, gpcEnabled: true })
  assert.equal(g.evaluate({ host: 'a.test', headers: { dnt: '1', 'sec-gpc': '1' } }).safe, true)
})

test('exempt domain flagged as forced off', () => {
  const r = reasons({ dntEnabled: true, exemptDomains: ['tracker.test'] }, { host: 'tracker.test', headers: {} })
  assert.ok(r.includes(DNT_REASON.DNT_FORCED_OFF))
})

test('uppercase header tolerated', () => {
  const g = new DntPreferenceGuard({ dntEnabled: true })
  assert.equal(g.evaluate({ host: 'a.test', headers: { DNT: '1' } }).safe, true)
})
