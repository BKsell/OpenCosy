'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CookieDomainGuard, CD_REASON } = require('./cookiedomainguard.js')

function reasons (i) {
  return new CookieDomainGuard().evaluate(i).findings.map((f) => f.reason)
}

test('host-only session cookie with samesite lax safe', () => {
  const r = new CookieDomainGuard().evaluate({
    setCookie: { name: 'sessionid', hostOnly: true, path: '/account', sameSite: 'Lax', secure: true },
    responseScheme: 'https', requestHost: 'https://app.x.test'
  })
  assert.equal(r.safe, true)
})

test('leading dot wildcard domain flagged', () => {
  const r = reasons({
    setCookie: { name: 'session', domain: '.x.test', sameSite: 'lax' },
    requestHost: 'https://app.x.test'
  })
  assert.ok(r.includes(CD_REASON.WILD_SUBDOMAIN_DOMAIN))
})

test('public suffix domain flagged', () => {
  const r = reasons({
    setCookie: { name: 'session', domain: 'github.io', sameSite: 'lax' },
    requestHost: 'https://evil.github.io'
  })
  assert.ok(r.includes(CD_REASON.PUBLIC_SUFFIX_DOMAIN))
})

test('sensitive cookie root path flagged', () => {
  assert.ok(reasons({ setCookie: { name: 'token', sameSite: 'strict', path: '/' } }).includes(CD_REASON.BROAD_PATH))
})

test('session cookie without samesite flagged', () => {
  assert.ok(reasons({ setCookie: { name: 'session', path: '/a' } }).includes(CD_REASON.MISSING_SAMESITE))
})

test('samesite none without secure flagged', () => {
  const r = reasons({ setCookie: { name: 'prefs', sameSite: 'None', secure: false } })
  assert.ok(r.includes(CD_REASON.SAMESITE_NONE_WITHOUT_SECURE))
})

test('secure cookie over http flagged', () => {
  const r = reasons({ setCookie: { name: 'prefs', sameSite: 'lax', secure: true }, responseScheme: 'http' })
  assert.ok(r.includes(CD_REASON.SECURE_ON_HTTP))
})

test('domain outside request host flagged', () => {
  const r = reasons({
    setCookie: { name: 'prefs', sameSite: 'lax', domain: 'evil.test' },
    requestHost: 'https://app.x.test'
  })
  assert.ok(r.some((x) => x.indexOf('scope') >= 0))
})
