'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { HeaderSplittingGuard, HS_REASON, hsValidName, sanitizeHeaderValue } = require('./headersplittingguard.js')

test('normal header safe', () => {
  assert.equal(new HeaderSplittingGuard().audit('x-file', 'report.pdf').safe, true)
})

test('crlf injection flagged', () => {
  const r = new HeaderSplittingGuard().audit('location', 'https://ok/\r\nSet-Cookie: a=1')
  assert.ok(r.findings.some((f) => f.reason === HS_REASON.CRLF_IN_VALUE))
})

test('bare lf injection flagged', () => {
  const r = new HeaderSplittingGuard().audit('x-note', 'a\nX-Evil: 1')
  assert.ok(r.findings.some((f) => f.reason === HS_REASON.CRLF_IN_VALUE))
})

test('nul flagged', () => {
  const r = new HeaderSplittingGuard().audit('x-note', 'a\x00b')
  assert.ok(r.findings.some((f) => f.reason === HS_REASON.NUL_IN_VALUE))
})

test('illegal header name flagged', () => {
  const g = new HeaderSplittingGuard()
  for (const n of ['bad name', 'a:b', '', 'x\r\ny']) {
    assert.equal(hsValidName(n), false, n)
    assert.equal(g.audit(n, 'v').safe, false, n)
  }
})

test('non-string value flagged', () => {
  const r = new HeaderSplittingGuard().audit('x-n', 1234)
  assert.ok(r.findings.some((f) => f.reason === HS_REASON.NON_STRING))
})

test('sanitize neutralizes line breaks', () => {
  assert.equal(sanitizeHeaderValue('  a\nb\r\nc\t '), 'a b c')
})

test('unicode value preserved', () => {
  assert.equal(new HeaderSplittingGuard().audit('x-n', '文件名 ✓').safe, true)
})
