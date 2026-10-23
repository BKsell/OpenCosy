'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HttpCredentialGuard, HC_REASON, hcHasUserInfo } = require('./httpcredentialguard.js')

function reasons (i) {
  return new HttpCredentialGuard().evaluate(i).findings.map((f) => f.reason)
}

test('plain https request without auth safe', () => {
  assert.equal(new HttpCredentialGuard().evaluate({ url: 'https://api.x.test/v1' }).safe, true)
})

test('url userinfo flagged', () => {
  assert.ok(hcHasUserInfo('https://user:pass@host/'))
  assert.ok(reasons({ url: 'https://user:pass@host/' }).includes(HC_REASON.URL_USERINFO))
})

test('ipv6 authority without userinfo not flagged', () => {
  assert.equal(hcHasUserInfo('https://[2001:db8::1]:443/'), false)
})

test('bearer over http flagged', () => {
  assert.ok(reasons({ url: 'http://h.test/', authorizationScheme: 'Bearer' }).includes(HC_REASON.CREDS_OVER_HTTP))
})

test('basic over http flagged specifically', () => {
  const r = reasons({ url: 'http://h.test/', authorizationScheme: 'Basic' })
  assert.ok(r.includes(HC_REASON.BASIC_OVER_HTTP))
  assert.ok(r.includes(HC_REASON.CREDS_OVER_HTTP))
})

test('weak auth scheme flagged', () => {
  assert.ok(reasons({ url: 'https://h.test/', authorizationScheme: 'Basic123' }).includes(HC_REASON.WEAK_SCHEME))
})

test('authorization stripped across host redirect', () => {
  const r = reasons({
    url: 'https://cdn.other.test/f',
    authorizationScheme: 'Bearer',
    redirectFrom: 'https://api.x.test/v1'
  })
  assert.ok(r.includes(HC_REASON.CREDS_FOLLOW_CROSS_HOST))
})

test('authorization may follow same host redirect', () => {
  const r = new HttpCredentialGuard().evaluate({
    url: 'https://h.test/login', authorizationScheme: 'Bearer', redirectFrom: 'https://h.test/old'
  })
  assert.equal(r.safe, true)
})

test('secret in query flagged', () => {
  assert.ok(reasons({ url: 'https://h.test/cb?api_key=abc' }).includes(HC_REASON.TOKEN_IN_QUERY))
})

test('second query secret flagged', () => {
  assert.ok(reasons({ url: 'https://h.test/cb?x=1&client_secret=s' }).includes(HC_REASON.TOKEN_IN_QUERY))
})

test('safe-looking param not flagged', () => {
  const r = reasons({ url: 'https://h.test/search?tokenizer=fast' })
  assert.ok(!r.includes(HC_REASON.TOKEN_IN_QUERY))
})
