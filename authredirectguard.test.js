'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { AuthRedirectGuard, AR_REASON } = require('./authredirectguard.js')

function reasons (i) {
  return new AuthRedirectGuard('app.x.test').evaluate(i).findings.map((f) => f.reason)
}

test('relative path safe', () => {
  assert.equal(new AuthRedirectGuard('app.x.test').evaluate({ target: '/dashboard' }).safe, true)
})

test('same-host absolute url safe', () => {
  assert.equal(new AuthRedirectGuard('app.x.test').evaluate({ target: 'https://app.x.test/home' }).safe, true)
})

test('foreign absolute url flagged', () => {
  assert.ok(reasons({ target: 'https://evil.test/p' }).includes(AR_REASON.ABSOLUTE_TO_FOREIGN_HOST))
})

test('protocol-relative flagged', () => {
  assert.ok(reasons({ target: '//evil.test/p' }).includes(AR_REASON.PROTOCOL_RELATIVE))
})

test('backslash bypass flagged', () => {
  assert.ok(reasons({ target: '/\\evil.test/p' }).includes(AR_REASON.BACKSLASH_BYPASS))
})

test('javascript scheme flagged', () => {
  assert.ok(reasons({ target: 'javascript:alert(1)' }).includes(AR_REASON.DANGEROUS_SCHEME))
})

test('data scheme flagged', () => {
  assert.ok(reasons({ target: 'data:text/html,x' }).includes(AR_REASON.DANGEROUS_SCHEME))
})

test('session fixation flagged after login', () => {
  const r = reasons({ target: '/home', authenticated: true, sessionBefore: 'S1', sessionAfter: 'S1' })
  assert.ok(r.includes(AR_REASON.SESSION_NOT_ROTATED))
})

test('rotated session safe', () => {
  const r = new AuthRedirectGuard('app.x.test').evaluate({
    target: '/home', authenticated: true, sessionBefore: 'S1', sessionAfter: 'S2'
  })
  assert.equal(r.safe, true)
})

test('token carried to foreign host flagged', () => {
  const r = reasons({ target: 'https://evil.test/cb?token=x', targetCarriesToken: true })
  assert.ok(r.includes(AR_REASON.TOKEN_LEAVING_HOST))
})
