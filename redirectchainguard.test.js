'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { RedirectChainGuard, RC_REASON, rcSchemeHost } = require('./redirectchainguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('normal https chain safe', () => {
  const r = new RedirectChainGuard().audit(['https://a.test/x', 'https://cdn.a.test/y'])
  assert.equal(r.safe, true)
})

test('downgrade to http flagged', () => {
  const r = new RedirectChainGuard().audit(['https://a.test/x', 'http://a.test/y'])
  assert.ok(reasons(r).includes(RC_REASON.DOWNGRADE))
})

test('jump to file scheme flagged', () => {
  const r = new RedirectChainGuard().audit(['https://a.test/x', 'file:///C:/secret'])
  assert.ok(reasons(r).includes(RC_REASON.NON_HTTP_TARGET))
})

test('jump to internal ip flagged', () => {
  const r = new RedirectChainGuard().audit(['https://a.test/x', 'http://169.254.169.254/latest/'])
  assert.ok(reasons(r).includes(RC_REASON.INTERNAL_TARGET))
})

test('redirect loop flagged', () => {
  const r = new RedirectChainGuard().audit(['https://a.test/x', 'https://a.test/x'])
  assert.ok(reasons(r).includes(RC_REASON.REDIRECT_LOOP))
})

test('too many hops flagged', () => {
  const chain = ['https://a.test/0']
  for (let i = 1; i <= 8; i++) chain.push('https://a.test/' + i)
  const r = new RedirectChainGuard(5).audit(chain)
  assert.ok(reasons(r).includes(RC_REASON.TOO_MANY_HOPS))
})

test('empty chain flagged', () => {
  const r = new RedirectChainGuard().audit([])
  assert.ok(reasons(r).includes(RC_REASON.EMPTY_URL))
})

test('scheme/host parse strips port userinfo and fragment', () => {
  const sh = rcSchemeHost('https://u:p@host.example:8443/path#frag')
  assert.equal(sh.scheme, 'https')
  assert.equal(sh.host, 'host.example')
})

test('ipv6 bracketed host parsed', () => {
  const sh = rcSchemeHost('https://[2001:db8::1]:443/')
  assert.equal(sh.host, '2001:db8::1')
})
