'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WebSocketUrlGuard, WU_REASON } = require('./websocketurlguard.js')

function reasons (i) {
  return new WebSocketUrlGuard().evaluate(i).findings.map((f) => f.reason)
}

test('wss on secure page safe', () => {
  assert.equal(new WebSocketUrlGuard().evaluate({ url: 'wss://push.example.com/ws', pageScheme: 'https' }).safe, true)
})

test('plain http page ws allowed (no downgrade)', () => {
  const r = reasons({ url: 'ws://h.test/ws', pageScheme: 'http' })
  assert.ok(!r.includes(WU_REASON.DOWNGRADE))
})

test('wss downgraded on https page flagged', () => {
  assert.ok(reasons({ url: 'ws://h.test/ws', pageScheme: 'https' }).includes(WU_REASON.DOWNGRADE))
})

test('non-ws scheme flagged', () => {
  assert.ok(reasons({ url: 'http://h.test/' }).includes(WU_REASON.BAD_SCHEME))
})

test('internal target flagged by default', () => {
  assert.ok(reasons({ url: 'ws://127.0.0.1:9000/ws' }).includes(WU_REASON.INTERNAL_TARGET))
  assert.ok(reasons({ url: 'ws://169.254.169.254/ws' }).includes(WU_REASON.INTERNAL_TARGET))
})

test('internal target allowed when opted in', () => {
  const r = new WebSocketUrlGuard().evaluate({ url: 'ws://127.0.0.1:9000/ws', allowInternal: true })
  assert.ok(!r.findings.some((f) => f.reason === WU_REASON.INTERNAL_TARGET))
})

test('token in query flagged', () => {
  assert.ok(reasons({ url: 'wss://h/ws?token=abc' }).includes(WU_REASON.TOKEN_IN_QUERY))
})

test('prefixed param name not falsely flagged', () => {
  const r = reasons({ url: 'wss://h/ws?not_token=abc' })
  assert.ok(!r.includes(WU_REASON.TOKEN_IN_QUERY))
})

test('second param token flagged', () => {
  assert.ok(reasons({ url: 'wss://h/ws?id=1&access_token=x' }).includes(WU_REASON.TOKEN_IN_QUERY))
})

test('empty host flagged', () => {
  assert.ok(reasons({ url: 'wss:///path' }).includes(WU_REASON.EMPTY_HOST))
})
