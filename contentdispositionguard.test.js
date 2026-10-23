'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ContentDispositionGuard, cdBaseName, CD_REASON } = require('./contentdispositionguard.js')

function reasonsOf (r) {
  return r.findings.map((f) => f.reason)
}

test('safe attachment filename', () => {
  const g = new ContentDispositionGuard()
  assert.equal(g.evaluate('attachment; filename="report.pdf"').safe, true)
})

test('bare filename safe', () => {
  const g = new ContentDispositionGuard()
  assert.equal(g.evaluate('photo.png').safe, true)
})

test('crlf injection flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('attachment; filename="a.pdf"\r\nEvil: 1')).includes(CD_REASON.CRLF_INJECTION))
})

test('path traversal flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('attachment; filename="../../etc/passwd"')).includes(CD_REASON.PATH_TRAVERSAL))
})

test('windows drive absolute flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('attachment; filename="C:\\\\Windows\\\\x"')).includes(CD_REASON.ABSOLUTE_PATH))
})

test('executable extension flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('attachment; filename="update.exe"')).includes(CD_REASON.EXECUTABLE_EXTENSION))
})

test('html extension flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('attachment; filename="page.html"')).includes(CD_REASON.EXECUTABLE_EXTENSION))
})

test('unknown disposition type flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('weird; filename="a.pdf"')).includes(CD_REASON.UNKNOWN_TYPE))
})

test('empty flagged', () => {
  const g = new ContentDispositionGuard()
  assert.ok(reasonsOf(g.evaluate('')).includes(CD_REASON.EMPTY))
})

test('filename star matching safe', () => {
  const g = new ContentDispositionGuard()
  const r = g.evaluate("attachment; filename=\"a b.pdf\"; filename*=UTF-8''a%20b.pdf")
  assert.equal(r.safe, true, JSON.stringify(r.findings))
})

test('basename strips both separators', () => {
  assert.equal(cdBaseName('a\\b/c.txt'), 'c.txt')
})
