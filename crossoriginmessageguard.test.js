'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CrossOriginMessageGuard, CM_REASON } = require('./crossoriginmessageguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

const g = new CrossOriginMessageGuard(['https://help.example.com', 'https://panel.example.com'])

test('send to explicit target safe', () => {
  assert.equal(g.auditSend('https://help.example.com', { type: 'ready' }).safe, true)
})

test('send to wildcard flagged', () => {
  const r = g.auditSend('*', { type: 'token' })
  assert.ok(reasons(r).includes(CM_REASON.WILDCARD_TARGET))
})

test('send primitive payload flagged', () => {
  const r = g.auditSend('https://help.example.com', 'raw-string')
  assert.ok(reasons(r).includes(CM_REASON.DATA_NOT_OBJECT))
})

test('receive from allowed origin safe', () => {
  const r = g.auditReceive({ origin: 'https://panel.example.com', data: { cmd: 'ping' } })
  assert.equal(r.safe, true)
})

test('receive case-insensitive allowed origin', () => {
  const r = g.auditReceive({ origin: 'https://PANEL.example.com', data: { cmd: 'ping' } })
  assert.equal(r.safe, true)
})

test('receive from attacker origin flagged', () => {
  const r = g.auditReceive({ origin: 'https://evil.test', data: { cmd: 'ping' } })
  assert.ok(reasons(r).includes(CM_REASON.ORIGIN_NOT_ALLOWED))
})

test('suffix-lookalike not allowed (exact match only)', () => {
  // evilexample.com 与 help.example.com 不应被后缀宽松匹配放行
  assert.equal(g.isOriginAllowed('https://help.example.com.evil.test'), false)
})

test('null origin flagged', () => {
  const r = g.auditReceive({ origin: 'null', data: {} })
  assert.ok(reasons(r).includes(CM_REASON.EMPTY_ORIGIN))
})

test('array payload flagged', () => {
  const r = g.auditReceive({ origin: 'https://help.example.com', data: [1, 2] })
  assert.ok(reasons(r).includes(CM_REASON.DATA_NOT_OBJECT))
})
