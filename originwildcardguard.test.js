'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { OriginWildcardGuard, OW_REASON } = require('./originwildcardguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('exact origin pattern safe', () => {
  assert.equal(new OriginWildcardGuard().auditPattern('https://app.example.com').safe, true)
})

test('star alone is fine without credentials', () => {
  assert.equal(new OriginWildcardGuard().auditPattern('*').safe, true)
})

test('subdomain wildcard is acceptable', () => {
  assert.equal(new OriginWildcardGuard().auditPattern('https://*.example.com').safe, true)
})

test('bare tld wildcard too broad', () => {
  const r = new OriginWildcardGuard().auditPattern('https://*.com')
  assert.ok(reasons(r).includes(OW_REASON.BAD_WILDCARD))
})

test('multiple stars too broad', () => {
  const r = new OriginWildcardGuard().auditPattern('https://*.*.example.com')
  assert.ok(reasons(r).includes(OW_REASON.BAD_WILDCARD))
})

test('star not at label start too broad', () => {
  const r = new OriginWildcardGuard().auditPattern('https://ap*.example.com')
  assert.ok(reasons(r).includes(OW_REASON.BAD_WILDCARD))
})

test('null pattern flagged', () => {
  const r = new OriginWildcardGuard().auditPattern('null')
  assert.ok(reasons(r).includes(OW_REASON.NULL_ORIGIN))
})

test('schemeless pattern flagged', () => {
  const r = new OriginWildcardGuard().auditPattern('app.example.com')
  assert.ok(reasons(r).includes(OW_REASON.SCHEMELESS))
})

test('wildcard with credentials in response flagged', () => {
  const r = new OriginWildcardGuard().auditResponse({
    acao: '*',
    allowCredentials: true
  })
  assert.ok(reasons(r).includes(OW_REASON.WILDCARD_WITH_CREDS))
})

test('reflect-any response flagged', () => {
  const r = new OriginWildcardGuard().auditResponse({
    reflectAny: true,
    requestOrigin: 'https://evil.test'
  })
  assert.ok(reasons(r).includes(OW_REASON.REFLECT_ANY))
})

test('null origin response flagged', () => {
  const r = new OriginWildcardGuard().auditResponse({ acao: 'null' })
  assert.ok(reasons(r).includes(OW_REASON.NULL_ORIGIN))
})
