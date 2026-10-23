'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { SetCookieSecurityGuard, parseSetCookie, SCS_REASON } = require('./setcookiesecurityguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const GOOD = 'sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/'

test('good session cookie safe', () => {
  const g = new SetCookieSecurityGuard()
  assert.equal(g.evaluate(GOOD).safe, true)
})

test('missing secure', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('sid=abc; HttpOnly; SameSite=Strict; Path=/')).includes(SCS_REASON.MISSING_SECURE))
})

test('missing httponly', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('sid=abc; Secure; SameSite=Strict; Path=/')).includes(SCS_REASON.MISSING_HTTPONLY))
})

test('missing samesite', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('sid=abc; Secure; HttpOnly; Path=/')).includes(SCS_REASON.MISSING_SAMESITE))
})

test('samesite none without secure', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('sid=abc; HttpOnly; SameSite=None; Path=/')).includes(SCS_REASON.SAMESITE_NONE_WITHOUT_SECURE))
})

test('invalid samesite value', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('sid=abc; Secure; HttpOnly; SameSite=Banana; Path=/')).includes(SCS_REASON.INVALID_SAMESITE))
})

test('domain attribute broadened', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('sid=abc; Secure; HttpOnly; SameSite=Strict; Domain=example.com')).includes(SCS_REASON.BROAD_DOMAIN))
})

test('__host- prefix requires secure no-domain path-slash', () => {
  const g = new SetCookieSecurityGuard()
  assert.equal(g.evaluate('__Host-sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/').safe, true)
  assert.ok(reasonsOf(g.evaluate('__Host-sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/x')).includes(SCS_REASON.HOST_PREFIX_VIOLATION))
})

test('__secure- prefix requires secure', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate('__Secure-sid=abc; HttpOnly; SameSite=Strict; Path=/')).includes(SCS_REASON.SECURE_PREFIX_VIOLATION))
})

test('control char flagged', () => {
  const g = new SetCookieSecurityGuard()
  assert.ok(reasonsOf(g.evaluate(GOOD + '\nEvil: 1')).includes(SCS_REASON.CONTROL_CHAR))
})

test('parser attrs', () => {
  const p = parseSetCookie(GOOD)
  assert.equal(p.name, 'sid')
  assert.equal(p.attrs.secure, true)
  assert.equal(p.attrs.sameSite, 'strict')
})
