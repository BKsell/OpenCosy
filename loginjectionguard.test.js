'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { LogInjectionGuard, LI_REASON, sanitizeLog, liHasReason } = require('./loginjectionguard.js')

test('plain log value safe', () => {
  assert.equal(new LogInjectionGuard().evaluate('download complete').safe, true)
})

test('crlf flagged', () => {
  const r = new LogInjectionGuard().evaluate('ok\n[INFO] forged')
  assert.equal(r.safe, false)
  assert.ok(liHasReason(r.findings, LI_REASON.CRLF))
})

test('carriage return only flagged', () => {
  const r = new LogInjectionGuard().evaluate('ok\rforged')
  assert.ok(liHasReason(r.findings, LI_REASON.CRLF))
})

test('ansi escape flagged', () => {
  const r = new LogInjectionGuard().evaluate('x\x1b[2Jclear')
  assert.ok(liHasReason(r.findings, LI_REASON.ANSI))
})

test('nul flagged', () => {
  const r = new LogInjectionGuard().evaluate('a\x00b')
  assert.ok(liHasReason(r.findings, LI_REASON.NUL))
})

test('other c0 control flagged', () => {
  const r = new LogInjectionGuard().evaluate('a\x07b')
  assert.ok(liHasReason(r.findings, LI_REASON.CONTROL))
})

test('sanitize produces single line', () => {
  assert.equal(sanitizeLog('a\nb\x1b[2Jc'), 'a_b_c')
})

test('sanitize strips DEL', () => {
  assert.equal(sanitizeLog('a\x7fb'), 'ab')
})

test('sanitize keeps unicode and punctuation', () => {
  assert.equal(sanitizeLog('报告: 100% done ✓'), '报告: 100% done ✓')
})

test('non-string coerced', () => {
  assert.equal(new LogInjectionGuard().evaluate(42).safe, true)
})
