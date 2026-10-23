'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { CsvFormulaGuard, CSV_REASON, sanitizeCell, buildRow } = require('./csvformulaguard.js')

test('normal text safe', () => {
  assert.equal(new CsvFormulaGuard().auditCell('Minecraft 1.20').safe, true)
})

test('formula triggers flagged', () => {
  const g = new CsvFormulaGuard()
  for (const v of ['=1+1', '+1', '-1', '@SUM(A1)']) {
    assert.equal(g.auditCell(v).safe, false, v)
    assert.ok(g.auditCell(v).findings.some((f) => f.reason === CSV_REASON.FORMULA_PREFIX), v)
  }
})

test('negative number also treated as trigger (excel parses as formula)', () => {
  assert.equal(new CsvFormulaGuard().auditCell('-42').safe, false)
})

test('sanitize prefixes apostrophe', () => {
  assert.equal(sanitizeCell('=HYPERLINK("http://x")'), "'=HYPERLINK(\"http://x\")")
})

test('plain cell not prefixed', () => {
  assert.equal(sanitizeCell('hello'), 'hello')
})

test('leading tab neutralized', () => {
  assert.equal(sanitizeCell('\t=1'), "'\t=1")
})

test('row quoting for comma and quotes', () => {
  assert.equal(buildRow(['a,b', 'he said "hi"', 'plain']), '"a,b","he said ""hi""",plain')
})

test('control character flagged', () => {
  const r = new CsvFormulaGuard().auditCell('a\x07b')
  assert.ok(r.findings.some((f) => f.reason === CSV_REASON.CONTROL_CHAR))
})

test('newline inside cell quoted not flagged', () => {
  const r = new CsvFormulaGuard().auditCell('line1\nline2')
  assert.equal(r.safe, true)
})
