'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CookiePrefixGuard, CP_REASON } = require('./cookieprefixguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('plain cookie name unaffected', () => {
  assert.equal(new CookiePrefixGuard().audit({ name: 'sid', secure: false, path: '/' }).safe, true)
})

test('valid __Host- cookie', () => {
  const r = new CookiePrefixGuard().audit({
    name: '__Host-sid', secure: true, path: '/', domain: '', sameSite: 'Strict'
  })
  assert.equal(r.safe, true)
})

test('__Host- must be secure', () => {
  const r = new CookiePrefixGuard().audit({ name: '__Host-sid', secure: false, path: '/' })
  assert.ok(reasons(r).includes(CP_REASON.HOST_NOT_SECURE))
})

test('__Host- must have path slash', () => {
  const r = new CookiePrefixGuard().audit({ name: '__Host-sid', secure: true, path: '/app' })
  assert.ok(reasons(r).includes(CP_REASON.HOST_BAD_PATH))
})

test('__Host- must not set domain', () => {
  const r = new CookiePrefixGuard().audit({
    name: '__Host-sid', secure: true, path: '/', domain: '.example.com'
  })
  assert.ok(reasons(r).includes(CP_REASON.HOST_HAS_DOMAIN))
})

test('__Host- must not be SameSite=None', () => {
  const r = new CookiePrefixGuard().audit({
    name: '__Host-sid', secure: true, path: '/', sameSite: 'None'
  })
  assert.ok(reasons(r).includes(CP_REASON.HOST_SAMESITE_NONE))
})

test('__Secure- must be secure', () => {
  const r = new CookiePrefixGuard().audit({ name: '__Secure-id', secure: false, path: '/' })
  assert.ok(reasons(r).includes(CP_REASON.SECURE_NOT_SECURE))
})

test('valid __Secure- cookie', () => {
  const r = new CookiePrefixGuard().audit({
    name: '__Secure-id', secure: true, path: '/', domain: '.example.com'
  })
  assert.equal(r.safe, true)
})

test('case-insensitive prefix matched', () => {
  const r = new CookiePrefixGuard().audit({ name: '__HOST-sid', secure: false, path: '/' })
  assert.ok(reasons(r).includes(CP_REASON.HOST_NOT_SECURE))
})

test('empty name after prefix flagged', () => {
  const r = new CookiePrefixGuard().audit({ name: '__Host-', secure: true, path: '/' })
  assert.ok(reasons(r).includes(CP_REASON.PREFIX_NAME_EMPTY))
})
