'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CspReportGuard, CR_REASON, crDirective } = require('./cspreportguard.js')

function reasons (i) {
  return new CspReportGuard().evaluate(i).findings.map((f) => f.reason)
}

const GOOD_CSP = "default-src 'self'; report-to csp-endpoint; report-uri https://app.x.test/csp"

test('directive lookup finds value', () => {
  assert.equal(crDirective('default-src self; report-uri https://h.test/r', 'report-uri'), 'https://h.test/r')
})

test('enforce csp with same-host endpoint safe', () => {
  const r = new CspReportGuard().evaluate({
    headerKind: 'enforce', csp: GOOD_CSP, policyHost: 'app.x.test'
  })
  assert.equal(r.safe, true)
})

test('no reporting endpoint flagged', () => {
  assert.ok(reasons({ headerKind: 'enforce', csp: "default-src 'self'" }).includes(CR_REASON.REPORTING_MISSING))
})

test('report-only flagged as not blocking', () => {
  assert.ok(reasons({ headerKind: 'report-only', csp: GOOD_CSP, policyHost: 'app.x.test' }).includes(CR_REASON.REPORT_ONLY_ASSUMED_ENFORCING))
})

test('deprecated report-uri without report-to flagged', () => {
  const csp = "default-src 'self'; report-uri https://app.x.test/csp"
  assert.ok(reasons({ headerKind: 'enforce', csp: csp, policyHost: 'app.x.test' }).includes(CR_REASON.REPORT_URI_DEPRECATED_ONLY))
})

test('http report uri flagged', () => {
  const csp = "default-src 'self'; report-uri http://app.x.test/csp"
  assert.ok(reasons({ headerKind: 'enforce', csp: csp }).includes(CR_REASON.REPORT_URI_HTTP))
})

test('foreign report host flagged', () => {
  const csp = "default-src 'self'; report-to ep; report-uri https://evil.test/csp"
  assert.ok(reasons({ headerKind: 'enforce', csp: csp, policyHost: 'app.x.test' }).includes(CR_REASON.REPORT_URI_FOREIGN))
})
