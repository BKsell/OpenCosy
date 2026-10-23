'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { PostMessageTargetGuard, pmtIsOriginLiteral, PMT_REASON } = require('./postmessagetargetguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('explicit https origin safe', () => {
  const g = new PostMessageTargetGuard()
  assert.equal(g.evaluate({ targetOrigin: 'https://app.test', pageSecure: true }).safe, true)
})

test('wildcard rejected', () => {
  const g = new PostMessageTargetGuard()
  assert.ok(reasonsOf(g.evaluate({ targetOrigin: '*' })).includes(PMT_REASON.WILDCARD_TARGET))
})

test('empty target rejected', () => {
  const g = new PostMessageTargetGuard()
  assert.ok(reasonsOf(g.evaluate({ targetOrigin: '  ' })).includes(PMT_REASON.EMPTY_TARGET))
})

test('slash same-origin safe', () => {
  const g = new PostMessageTargetGuard()
  assert.equal(g.evaluate({ targetOrigin: '/' }).sameOrigin, true)
})

test('http target from secure page flagged', () => {
  const g = new PostMessageTargetGuard()
  assert.ok(reasonsOf(g.evaluate({ targetOrigin: 'http://app.test', pageSecure: true })).includes(PMT_REASON.INSECURE_TARGET))
})

test('http target from http page allowed', () => {
  const g = new PostMessageTargetGuard()
  assert.equal(g.evaluate({ targetOrigin: 'http://app.test', pageSecure: false }).safe, true)
})

test('malformed origin', () => {
  const g = new PostMessageTargetGuard()
  assert.ok(reasonsOf(g.evaluate({ targetOrigin: 'app.test' })).includes(PMT_REASON.MALFORMED_ORIGIN))
})

test('wildcard allowed for same-origin under policy', () => {
  const g = new PostMessageTargetGuard({ allowWildcardSameOrigin: true })
  assert.equal(g.evaluate({ targetOrigin: '*', sameOriginTarget: true }).safe, true)
})

test('origin literal parser', () => {
  assert.equal(pmtIsOriginLiteral('/').sameOrigin, true)
  assert.equal(pmtIsOriginLiteral('https://a.test').ok, true)
  assert.equal(pmtIsOriginLiteral('https://a.test/x').ok, false)
})
