'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OpenRedirectGuard, ORD_REASON } = require('./openredirectguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

function guard () {
  return new OpenRedirectGuard({ allowedOrigins: ['https://app.test', 'https://app.test:8443'] })
}

test('relative path safe', () => {
  assert.equal(guard().evaluate('/dashboard').safe, true)
})

test('query-only safe', () => {
  assert.equal(guard().evaluate('?next=x').safe, true)
})

test('external absolute denied', () => {
  assert.ok(reasonsOf(guard().evaluate('https://evil.test')).includes(ORD_REASON.EXTERNAL_ABSOLUTE))
})

test('allowed absolute origin safe', () => {
  assert.equal(guard().evaluate('https://app.test/cb').safe, true)
})

test('protocol-relative denied', () => {
  assert.ok(reasonsOf(guard().evaluate('//evil.test')).includes(ORD_REASON.PROTOCOL_RELATIVE))
})

test('backslash protocol-relative denied', () => {
  assert.ok(reasonsOf(guard().evaluate('/\\evil.test')).includes(ORD_REASON.PROTOCOL_RELATIVE))
})

test('leading backslash denied', () => {
  assert.ok(reasonsOf(guard().evaluate('\\evil.test')).includes(ORD_REASON.BACKSLASH_HOST))
})

test('userinfo spoof denied', () => {
  assert.ok(reasonsOf(guard().evaluate('https://app.test@evil.test')).includes(ORD_REASON.USERINFO_HOST))
})

test('javascript scheme denied', () => {
  assert.ok(reasonsOf(guard().evaluate('javascript:alert(1)')).includes(ORD_REASON.NON_HTTP_SCHEME))
})

test('bare hostname denied by default', () => {
  assert.ok(reasonsOf(guard().evaluate('evil.test')).includes(ORD_REASON.BARE_HOST))
})

test('missing-slash https denied', () => {
  assert.ok(reasonsOf(guard().evaluate('https:evil.test')).includes(ORD_REASON.EXTERNAL_ABSOLUTE))
})

test('leading whitespace external still caught', () => {
  assert.ok(reasonsOf(guard().evaluate('  https://evil.test')).includes(ORD_REASON.EXTERNAL_ABSOLUTE))
})

test('control char flagged', () => {
  assert.ok(reasonsOf(guard().evaluate('/a\n')).includes(ORD_REASON.CONTROL_OR_WHITESPACE))
})

test('empty target denied', () => {
  assert.ok(reasonsOf(guard().evaluate('')).includes(ORD_REASON.EMPTY_TARGET))
})

test('suffix does not bypass allowlist', () => {
  assert.ok(reasonsOf(guard().evaluate('https://app.test.evil.test')).includes(ORD_REASON.EXTERNAL_ABSOLUTE))
})
