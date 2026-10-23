'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { MixedFormActionGuard, MFA_REASON, mfaParseAction } = require('./mixedformactionguard.js')

function reasons (i) {
  return new MixedFormActionGuard().evaluate(i).findings.map((f) => f.reason)
}

test('https form to https same host safe', () => {
  const r = new MixedFormActionGuard().evaluate({
    pageScheme: 'https', pageHost: 'a.test', action: 'https://a.test/login'
  })
  assert.equal(r.safe, true)
})

test('relative action on https safe', () => {
  const r = new MixedFormActionGuard().evaluate({ pageScheme: 'https', pageHost: 'a.test', action: '/login' })
  assert.equal(r.safe, true)
})

test('https page form to http flagged', () => {
  const r = reasons({ pageScheme: 'https', pageHost: 'a.test', action: 'http://a.test/login' })
  assert.ok(r.includes(MFA_REASON.FORM_TO_HTTP))
})

test('protocol relative action flagged', () => {
  const r = reasons({ pageScheme: 'https', pageHost: 'a.test', action: '//a.test/login' })
  assert.ok(r.includes(MFA_REASON.ACTION_PROTOCOL_RELATIVE))
})

test('javascript action flagged', () => {
  const r = reasons({ pageScheme: 'https', pageHost: 'a.test', action: 'javascript:alert(1)' })
  assert.ok(r.includes(MFA_REASON.NON_HTTP_SCHEME))
})

test('cross-origin form flagged', () => {
  const r = reasons({ pageScheme: 'https', pageHost: 'a.test', action: 'https://collector.other/x' })
  assert.ok(r.includes(MFA_REASON.CROSS_ORIGIN_FORM))
})

test('parse scheme normalized without colon', () => {
  assert.equal(mfaParseAction('http://h/x', 'https').scheme, 'http')
  assert.equal(mfaParseAction('/rel', 'https').scheme, 'https')
})
