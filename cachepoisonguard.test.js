'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CachePoisonGuard, CP2_REASON, cpParseCacheControl } = require('./cachepoisonguard.js')

function reasons (i) {
  return new CachePoisonGuard().evaluate(i).findings.map((f) => f.reason)
}

test('parse cache-control', () => {
  const cc = cpParseCacheControl('public, max-age=60')
  assert.equal(cc.public, true)
  assert.equal(cc.maxAge, 60)
})

test('public response depending on x-forwarded-host flagged', () => {
  const r = reasons({
    cacheControl: 'public, max-age=60',
    usedRequestHeaders: ['X-Forwarded-Host']
  })
  assert.ok(r.includes(CP2_REASON.UNKEYED_HEADER_REFLECTED))
})

test('same response private is safe', () => {
  const r = new CachePoisonGuard().evaluate({
    cacheControl: 'private',
    usedRequestHeaders: ['X-Forwarded-Host']
  })
  assert.equal(r.safe, true)
})

test('set-cookie on public cache flagged', () => {
  assert.ok(reasons({ cacheControl: 'public, max-age=60', setCookie: true }).includes(CP2_REASON.SET_COOKIE_CACHED))
})

test('auth response public cached flagged', () => {
  assert.ok(reasons({ cacheControl: 'public, max-age=60', hasAuthHeader: true }).includes(CP2_REASON.AUTH_RESPONSE_CACHED))
})

test('dynamic html with query public cached flagged', () => {
  const r = reasons({
    cacheControl: 'public, max-age=30',
    url: 'https://h.test/search?q=1',
    contentType: 'text/html; charset=utf-8'
  })
  assert.ok(r.includes(CP2_REASON.DYNAMIC_HTML_CACHED))
})

test('static asset with query cacheable safe', () => {
  const r = new CachePoisonGuard().evaluate({
    cacheControl: 'public, max-age=30',
    url: 'https://h.test/app.js?v=2',
    contentType: 'application/javascript'
  })
  assert.equal(r.safe, true)
})

test('redirect carrying token in location cached flagged', () => {
  const r = reasons({
    cacheControl: 'public, max-age=30',
    status: 302,
    location: 'https://h.test/cb?token=abc'
  })
  assert.ok(r.includes(CP2_REASON.REDIRECT_CACHED))
})

test('redirect with prefixed param not flagged', () => {
  const r = new CachePoisonGuard().evaluate({
    cacheControl: 'public, max-age=30',
    status: 302,
    location: 'https://h.test/p?not_token=x'
  })
  assert.equal(r.safe, true)
})

test('no-store disables shared-cache checks', () => {
  const r = new CachePoisonGuard().evaluate({
    cacheControl: 'no-store', setCookie: true, hasAuthHeader: true
  })
  assert.equal(r.safe, true)
})
