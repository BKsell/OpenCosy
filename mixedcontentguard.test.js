'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MixedContentGuard, mcClassifyType, MC_ACTION, MC_KIND, MC_REASON } = require('./mixedcontentguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const HTTPS = { pageScheme: 'https' }

test('active http script blocked', () => {
  const g = new MixedContentGuard()
  const r = g.evaluate({ url: 'http://cdn.test/a.js', type: 'script' }, HTTPS)
  assert.equal(r.action, MC_ACTION.BLOCK)
  assert.ok(reasonsOf(r).includes(MC_REASON.ACTIVE_MIXED))
})

test('passive http image upgraded', () => {
  const g = new MixedContentGuard()
  const r = g.evaluate({ url: 'http://cdn.test/a.png', type: 'image' }, HTTPS)
  assert.equal(r.action, MC_ACTION.UPGRADE)
  assert.ok(reasonsOf(r).includes(MC_REASON.PASSIVE_MIXED))
})

test('ws from https blocked', () => {
  const g = new MixedContentGuard()
  const r = g.evaluate({ url: 'ws://s.test/socket', type: 'websocket' }, HTTPS)
  assert.equal(r.action, MC_ACTION.BLOCK)
  assert.ok(reasonsOf(r).includes(MC_REASON.INSECURE_WS))
})

test('wss allowed', () => {
  const g = new MixedContentGuard()
  assert.equal(g.evaluate({ url: 'wss://s.test/socket', type: 'websocket' }, HTTPS).action, MC_ACTION.ALLOW)
})

test('https script allowed', () => {
  const g = new MixedContentGuard()
  assert.equal(g.evaluate({ url: 'https://cdn.test/a.js', type: 'script' }, HTTPS).action, MC_ACTION.ALLOW)
})

test('data uri allowed', () => {
  const g = new MixedContentGuard()
  assert.equal(g.evaluate({ url: 'data:image/png;base64,xx', type: 'image' }, HTTPS).action, MC_ACTION.ALLOW)
})

test('http page does not apply', () => {
  const g = new MixedContentGuard()
  assert.equal(g.evaluate({ url: 'http://cdn.test/a.js', type: 'script' }, { pageScheme: 'http' }).action, MC_ACTION.ALLOW)
})

test('untyped http treated conservatively', () => {
  const g = new MixedContentGuard()
  assert.equal(g.evaluate({ url: 'http://x.test/y' }, HTTPS).action, MC_ACTION.BLOCK)
})

test('policy can upgrade active instead of block', () => {
  const g = new MixedContentGuard({ blockActive: false })
  assert.equal(g.evaluate({ url: 'http://x.test/a.js', type: 'script' }, HTTPS).action, MC_ACTION.UPGRADE)
})

test('type classifier', () => {
  assert.equal(mcClassifyType('iframe'), MC_KIND.ACTIVE)
  assert.equal(mcClassifyType('video'), MC_KIND.PASSIVE)
  assert.equal(mcClassifyType('unknown-thing'), MC_KIND.NEUTRAL)
})
