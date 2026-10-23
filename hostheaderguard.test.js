'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HostHeaderGuard, HH_REASON } = require('./hostheaderguard.js')

function reasons (i) {
  return new HostHeaderGuard(['app.x.test', 'cdn.x.test'], [8443]).evaluate(i).findings.map((f) => f.reason)
}

test('allowed host default port safe', () => {
  assert.equal(new HostHeaderGuard(['app.x.test']).evaluate({ hostHeader: 'app.x.test' }).safe, true)
})

test('empty host flagged', () => {
  assert.ok(reasons({ hostHeader: '' }).includes(HH_REASON.EMPTY))
})

test('illegal char flagged', () => {
  assert.ok(reasons({ hostHeader: 'app.x.test @evil' }).includes(HH_REASON.ILLEGAL_CHAR))
})

test('host not in allowlist flagged', () => {
  assert.ok(reasons({ hostHeader: 'evil.test' }).includes(HH_REASON.NOT_ALLOWED))
})

test('leading dot flagged', () => {
  assert.ok(reasons({ hostHeader: '.app.x.test' }).includes(HH_REASON.LEADING_DOT))
})

test('mismatched serving port flagged', () => {
  assert.ok(reasons({ hostHeader: 'app.x.test:9999' }).includes(HH_REASON.PORT_MISMATCH))
})

test('configured port allowed', () => {
  const g = new HostHeaderGuard(['app.x.test'], [8443])
  assert.equal(g.evaluate({ hostHeader: 'app.x.test:8443' }).safe, true)
})

test('bad port flagged', () => {
  assert.ok(reasons({ hostHeader: 'app.x.test:abc' }).includes(HH_REASON.BAD_PORT))
})

test('authority mismatch flagged', () => {
  const r = reasons({ hostHeader: 'app.x.test', authority: 'app.x.test:8443' })
  assert.ok(r.includes(HH_REASON.AUTHORITY_MISMATCH))
})

test('bracketed ipv6 with port parsed', () => {
  const g = new HostHeaderGuard(['::1'], [8443])
  assert.equal(g.evaluate({ hostHeader: '[::1]:8443' }).safe, true)
})
