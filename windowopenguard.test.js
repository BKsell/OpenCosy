'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { WindowOpenGuard, wogParseFeatures, WOG_REASON } = require('./windowopenguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

const BASE = 'https://app.test'

test('cross-origin open with noopener token safe', () => {
  const g = new WindowOpenGuard()
  assert.equal(g.evaluate({ url: 'https://ext.test', target: '_blank', features: 'noopener', baseOrigin: BASE }).safe, true)
})

test('cross-origin open with noopener=yes safe', () => {
  const g = new WindowOpenGuard()
  assert.equal(g.evaluate({ url: 'https://ext.test', features: 'noopener=yes,width=400', baseOrigin: BASE }).safe, true)
})

test('cross-origin open with noreferrer safe', () => {
  const g = new WindowOpenGuard()
  assert.equal(g.evaluate({ url: 'https://ext.test', features: 'noreferrer', baseOrigin: BASE }).safe, true)
})

test('cross-origin open without features flagged', () => {
  const g = new WindowOpenGuard()
  assert.ok(reasonsOf(g.evaluate({ url: 'https://ext.test', baseOrigin: BASE })).includes(WOG_REASON.NEW_WINDOW_NO_OPENER))
})

test('noopener explicitly disabled flagged', () => {
  const g = new WindowOpenGuard()
  assert.ok(reasonsOf(g.evaluate({ url: 'https://ext.test', features: 'noopener=no', baseOrigin: BASE })).includes(WOG_REASON.NOOPENER_EXPLICITLY_DISABLED))
})

test('same-origin exempt by default', () => {
  const g = new WindowOpenGuard()
  assert.equal(g.evaluate({ url: 'https://app.test/p', baseOrigin: BASE }).safe, true)
})

test('non-blank target safe', () => {
  const g = new WindowOpenGuard()
  assert.equal(g.evaluate({ url: 'https://ext.test', target: '_self', baseOrigin: BASE }).safe, true)
})

test('unknown feature flagged only in strict', () => {
  const g = new WindowOpenGuard({ rejectUnknownFeatures: true })
  assert.ok(reasonsOf(g.evaluate({ url: 'https://ext.test', features: 'noopener,bogus=1', baseOrigin: BASE })).includes(WOG_REASON.UNKNOWN_FEATURE))
})

test('feature parser', () => {
  const f = wogParseFeatures('width=400,noopener')
  assert.equal(f.width, '400')
  assert.equal(f.noopener, 'true')
})
