'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WebSocketOriginGuard, wsoParseOrigin, WSO_REASON } = require('./websocketoriginguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

function guard () {
  return new WebSocketOriginGuard({ allowedOrigins: ['https://app.test', 'https://app.test:8443'] })
}

test('allowed origin for wss safe', () => {
  const g = guard()
  const r = g.evaluate('https://app.test', 'wss')
  assert.equal(r.safe, true)
})

test('allowed origin with port safe', () => {
  const g = guard()
  assert.equal(g.evaluate('https://app.test:8443', 'wss').safe, true)
})

test('disallowed origin rejected', () => {
  const g = guard()
  const r = g.evaluate('https://evil.test', 'wss')
  assert.ok(reasonsOf(r).includes(WSO_REASON.ORIGIN_NOT_ALLOWED))
})

test('suffix trick does not bypass', () => {
  const g = guard()
  const r = g.evaluate('https://app.test.evil.test', 'wss')
  assert.ok(reasonsOf(r).includes(WSO_REASON.ORIGIN_NOT_ALLOWED))
})

test('missing origin rejected by default', () => {
  const g = guard()
  assert.ok(reasonsOf(g.evaluate(null, 'wss')).includes(WSO_REASON.ORIGIN_MISSING))
})

test('missing origin allowed for non-browser policy', () => {
  const g = new WebSocketOriginGuard({ allowMissingOrigin: true })
  assert.equal(g.evaluate(null, 'wss').safe, true)
})

test('null origin rejected by default', () => {
  const g = guard()
  assert.ok(reasonsOf(g.evaluate('null', 'wss')).includes(WSO_REASON.ORIGIN_NULL))
})

test('http origin to wss scheme mismatch', () => {
  const g = new WebSocketOriginGuard({ allowedOrigins: ['http://app.test'] })
  const r = g.evaluate('http://app.test', 'wss')
  assert.ok(reasonsOf(r).includes(WSO_REASON.SCHEME_MISMATCH))
})

test('malformed origin', () => {
  const g = guard()
  assert.ok(reasonsOf(g.evaluate('not-an-origin', 'wss')).includes(WSO_REASON.ORIGIN_MALFORMED))
})

test('origin with path is malformed', () => {
  const g = guard()
  assert.ok(reasonsOf(g.evaluate('https://app.test/path', 'wss')).includes(WSO_REASON.ORIGIN_MALFORMED))
})

test('ipv6 origin parsed', () => {
  const p = wsoParseOrigin('https://[::1]:8443')
  assert.equal(p.port, '8443')
  assert.equal(p.host, '[::1]')
})

test('control char flagged', () => {
  const g = guard()
  assert.ok(reasonsOf(g.evaluate('https://app.test\r\n', 'wss')).includes(WSO_REASON.CONTROL_CHAR))
})
