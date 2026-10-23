'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { DownloadFilenameGuard, DF_REASON, sanitizeFilename } = require('./downloadfilenameguard.js')

function reasons (name) {
  return new DownloadFilenameGuard().audit(name).findings.map((f) => f.reason)
}

test('plain filename safe', () => {
  assert.equal(new DownloadFilenameGuard().audit('report-2026.pdf').safe, true)
})

test('path separator flagged', () => {
  assert.ok(reasons('..\\..\\evil.exe').includes(DF_REASON.PATH_SEPARATOR))
  assert.ok(reasons('a/b.txt').includes(DF_REASON.PATH_SEPARATOR))
})

test('parent traversal flagged', () => {
  assert.ok(reasons('../x').includes(DF_REASON.PARENT_TRAVERSAL))
})

test('ads colon flagged', () => {
  assert.ok(reasons('a.txt:secret').includes(DF_REASON.ADS_STREAM))
})

test('illegal chars flagged', () => {
  assert.ok(reasons('a?.txt').includes(DF_REASON.ILLEGAL_CHAR))
})

test('trailing dot and space flagged', () => {
  assert.ok(reasons('a.txt.').includes(DF_REASON.TRAILING_DOT_SPACE))
  assert.ok(reasons('a.txt ').includes(DF_REASON.TRAILING_DOT_SPACE))
})

test('reserved names flagged case-insensitive', () => {
  for (const n of ['CON', 'nul.txt', 'Com1']) {
    assert.ok(reasons(n).includes(DF_REASON.RESERVED_NAME), n)
  }
})

test('sanitize strips directory components', () => {
  assert.equal(sanitizeFilename('C:\\evil\\payload.exe').name, 'payload.exe')
  assert.equal(sanitizeFilename('../../startup.bat').name, 'startup.bat')
})

test('sanitize replaces illegal chars', () => {
  assert.equal(sanitizeFilename('a?b:c*.txt').name, 'a_b_c_.txt')
})

test('sanitize prefixes reserved name', () => {
  assert.equal(sanitizeFilename('NUL').name, '_NUL')
})

test('sanitize empties to fallback', () => {
  assert.equal(sanitizeFilename('///').name, 'download')
})

test('sanitize removes trailing dot', () => {
  assert.equal(sanitizeFilename('doc.pdf.').name, 'doc.pdf')
})
