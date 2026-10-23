'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { XssSinkGuard, XS_REASON } = require('./xsssinkguard.js')

function reasons (i) {
  return new XssSinkGuard().evaluate(i).findings.map((f) => f.reason)
}

test('textcontent from untrusted source is safe', () => {
  const r = new XssSinkGuard().evaluate({ sink: 'textContent', source: 'location.hash' })
  assert.equal(r.safe, true)
})

test('innerhtml from hash without sanitize flagged', () => {
  const r = reasons({ sink: 'innerHTML', source: 'location.hash' })
  assert.ok(r.includes(XS_REASON.HTML_SINK_WITH_RAW_INPUT))
  assert.ok(r.includes(XS_REASON.NO_SANITIZER))
})

test('innerhtml sanitized still flags source but not no-sanitizer', () => {
  const r = reasons({ sink: 'innerHTML', source: 'postMessage', sanitized: true })
  assert.ok(r.includes(XS_REASON.UNTRUSTED_SOURCE))
  assert.ok(!r.includes(XS_REASON.NO_SANITIZER))
})

test('document.write flagged', () => {
  assert.ok(reasons({ sink: 'document.write', source: 'fetch-response' }).includes(XS_REASON.DOC_WRITE))
})

test('eval from storage flagged', () => {
  assert.ok(reasons({ sink: 'eval', source: 'localStorage' }).includes(XS_REASON.SCRIPT_STRING_SINK))
})

test('settimeout string flagged', () => {
  assert.ok(reasons({ sink: 'setTimeout-string', source: 'window.name' }).includes(XS_REASON.SCRIPT_STRING_SINK))
})

test('javascript navigation flagged', () => {
  const r = reasons({ sink: 'location.href', source: 'location.search', value: 'javascript:alert(1)' })
  assert.ok(r.includes(XS_REASON.JAVASCRIPT_NAV))
})

test('trusted constant innerhtml declared safe', () => {
  const r = new XssSinkGuard().evaluate({ sink: 'innerHTML', untrusted: false })
  assert.equal(r.safe, true)
})
