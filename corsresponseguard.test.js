'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CorsResponseGuard, CORS_REASON } = require('./corsresponseguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('exact allowlisted origin with credentials safe', () => {
  const g = new CorsResponseGuard()
  const r = g.evaluate({ allowOrigin: 'https://app.test', allowCredentials: true, allowlistMatched: true, requestedOrigin: 'https://app.test' })
  assert.equal(r.safe, true, JSON.stringify(r.findings))
})

test('wildcard no credentials is permissive but not fatal', () => {
  const g = new CorsResponseGuard()
  const r = g.evaluate({ allowOrigin: '*', allowCredentials: false })
  assert.ok(reasonsOf(r).includes(CORS_REASON.WILDCARD_ANYWAY))
})

test('wildcard with credentials flagged', () => {
  const g = new CorsResponseGuard()
  const r = g.evaluate({ allowOrigin: '*', allowCredentials: true })
  assert.ok(reasonsOf(r).includes(CORS_REASON.WILDCARD_WITH_CREDENTIALS))
})

test('reflected origin with credentials flagged', () => {
  const g = new CorsResponseGuard()
  const r = g.evaluate({ allowOrigin: 'https://evil.test', allowCredentials: true, allowlistMatched: false, requestedOrigin: 'https://evil.test' })
  assert.ok(reasonsOf(r).includes(CORS_REASON.REFLECTED_ORIGIN_WITH_CREDENTIALS))
})

test('credentials origin not on allowlist flagged', () => {
  const g = new CorsResponseGuard()
  const r = g.evaluate({ allowOrigin: 'https://other.test', allowCredentials: true, allowlistMatched: false, requestedOrigin: 'https://evil.test' })
  assert.ok(reasonsOf(r).includes(CORS_REASON.CREDENTIALS_WITHOUT_ALLOWLIST))
})

test('null origin flagged', () => {
  const g = new CorsResponseGuard()
  assert.ok(reasonsOf(g.evaluate({ allowOrigin: 'null' })).includes(CORS_REASON.NULL_ORIGIN_ALLOWED))
})

test('multiple ACAO flagged', () => {
  const g = new CorsResponseGuard()
  const r = g.evaluate({ allowOriginList: ['https://a.test', 'https://b.test'] })
  assert.ok(reasonsOf(r).includes(CORS_REASON.MULTIPLE_ACAO))
})

test('no CORS header is safe (cross disabled)', () => {
  const g = new CorsResponseGuard()
  assert.equal(g.evaluate({}).safe, true)
})

test('control char flagged', () => {
  const g = new CorsResponseGuard()
  assert.ok(reasonsOf(g.evaluate({ allowOrigin: "https://a.test\r" })).includes(CORS_REASON.CONTROL_CHAR))
})
