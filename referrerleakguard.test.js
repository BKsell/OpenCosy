'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ReferrerLeakGuard, RL2_REASON } = require('./referrerleakguard.js')

function evalOne (o) {
  return new ReferrerLeakGuard().evaluate(o)
}

test('default policy trims to origin cross-origin', () => {
  const r = evalOne({
    policy: 'strict-origin-when-cross-origin',
    sourceUrl: 'https://a.test/path?x=1',
    targetUrl: 'https://b.test/'
  })
  assert.equal(r.allowedReferrer, 'https://a.test')
})

test('default policy sends full url same-origin', () => {
  const r = evalOne({
    policy: 'strict-origin-when-cross-origin',
    sourceUrl: 'https://a.test/p?q=1',
    targetUrl: 'https://a.test/x'
  })
  assert.equal(r.allowedReferrer, 'https://a.test/p?q=1')
})

test('default policy sends nothing on downgrade', () => {
  const r = evalOne({
    policy: 'strict-origin-when-cross-origin',
    sourceUrl: 'https://a.test/p',
    targetUrl: 'http://a.test/'
  })
  assert.equal(r.allowedReferrer, null)
})

test('no-referrer never sends', () => {
  const r = evalOne({ policy: 'no-referrer', sourceUrl: 'https://a.test/p', targetUrl: 'https://a.test/x' })
  assert.equal(r.allowedReferrer, null)
})

test('origin policy always only origin', () => {
  const r = evalOne({ policy: 'origin', sourceUrl: 'https://a.test/p', targetUrl: 'https://a.test/x' })
  assert.equal(r.allowedReferrer, 'https://a.test')
})

test('unsafe-url flagged', () => {
  const r = evalOne({ policy: 'unsafe-url', sourceUrl: 'https://a.test/p', targetUrl: 'https://b.test/' })
  assert.ok(r.findings.some((f) => f.reason === RL2_REASON.UNSAFE_POLICY))
  assert.ok(r.findings.some((f) => f.reason === RL2_REASON.FULL_URL_TO_CROSS_ORIGIN))
})

test('unsafe-url downgrade flagged', () => {
  const r = evalOne({ policy: 'unsafe-url', sourceUrl: 'https://a.test/p', targetUrl: 'http://a.test/' })
  assert.ok(r.findings.some((f) => f.reason === RL2_REASON.FULL_URL_ON_DOWNGRADE))
})

test('actual referrer longer than allowed flagged', () => {
  const r = evalOne({
    policy: 'strict-origin-when-cross-origin',
    sourceUrl: 'https://a.test/secret-path',
    targetUrl: 'https://b.test/',
    actualReferrer: 'https://a.test/secret-path'
  })
  assert.ok(r.findings.some((f) => f.reason === RL2_REASON.ACTUAL_EXCEEDS_POLICY))
})

test('actual referrer empty when null allowed safe', () => {
  const r = evalOne({
    policy: 'no-referrer',
    sourceUrl: 'https://a.test/p',
    targetUrl: 'https://b.test/',
    actualReferrer: ''
  })
  assert.equal(r.safe, true)
})

test('sending referrer when policy forbids flagged', () => {
  const r = evalOne({
    policy: 'no-referrer',
    sourceUrl: 'https://a.test/p',
    targetUrl: 'https://b.test/',
    actualReferrer: 'https://a.test/p'
  })
  assert.ok(r.findings.some((f) => f.reason === RL2_REASON.ACTUAL_EXCEEDS_POLICY))
})
