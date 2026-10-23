'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WebStorageGuard, WS2_REASON } = require('./webstorageguard.js')

function reasons (e) {
  return new WebStorageGuard().evaluate(e).findings.map((f) => f.reason)
}

test('benign preference in local safe', () => {
  assert.equal(new WebStorageGuard().evaluate({ area: 'local', key: 'theme', value: 'dark' }).safe, true)
})

test('access token in local flagged', () => {
  const r = reasons({ area: 'local', key: 'access_token' })
  assert.ok(r.includes(WS2_REASON.SENSITIVE_KEY_IN_LOCAL))
})

test('secret value in local flagged', () => {
  assert.ok(reasons({ area: 'local', key: 'session', classifiedAs: 'secret' }).includes(WS2_REASON.SENSITIVE_IN_LOCAL))
})

test('token in local without expiry flagged', () => {
  assert.ok(reasons({ area: 'local', key: 'token' }).includes(WS2_REASON.NO_EXPIRY))
})

test('token with expiry policy avoids no-expiry', () => {
  const r = new WebStorageGuard().evaluate({ area: 'local', key: 'token', hasExpiryPolicy: true })
  assert.ok(!r.findings.some((f) => f.reason === WS2_REASON.NO_EXPIRY))
})

test('token in session storage allowed', () => {
  const r = new WebStorageGuard().evaluate({ area: 'session', key: 'access_token' })
  assert.equal(r.safe, true)
})

test('pii card in any storage flagged', () => {
  assert.ok(reasons({ area: 'session', key: 'creditcard' }).includes(WS2_REASON.PII_IN_STORAGE))
})

test('logout leaves token flagged', () => {
  const r = new WebStorageGuard().auditLogout(['theme', 'refresh_token'])
  assert.ok(!r.safe)
  assert.ok(r.findings.some((f) => f.reason === WS2_REASON.SENSITIVE_KEY_IN_LOCAL))
})

test('logout clean safe', () => {
  assert.equal(new WebStorageGuard().auditLogout(['theme', 'locale']).safe, true)
})
