'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { ConstantCompareGuard, CC_REASON, timingSafeEqualString } = require('./constantcompareguard.js')

function reasons (r) {
  return r.findings.map((f) => f.reason)
}

test('equal strings compare true', () => {
  assert.equal(timingSafeEqualString('token-abc', 'token-abc'), true)
})

test('different strings compare false', () => {
  assert.equal(timingSafeEqualString('token-abc', 'token-abd'), false)
})

test('different length false without throw', () => {
  assert.equal(timingSafeEqualString('abc', 'abcdef'), false)
})

test('both empty are equal', () => {
  assert.equal(timingSafeEqualString('', ''), true)
})

test('non-string inputs safe false', () => {
  assert.equal(timingSafeEqualString(null, 'x'), false)
  assert.equal(timingSafeEqualString(1, 1), false)
})

test('audit length mismatch', () => {
  const r = new ConstantCompareGuard().auditInputs('aaa', 'bbbb')
  assert.ok(reasons(r).includes(CC_REASON.LENGTH_MISMATCH))
})

test('audit non-string', () => {
  const r = new ConstantCompareGuard().auditInputs(undefined, 'x')
  assert.ok(reasons(r).includes(CC_REASON.NON_STRING))
})

test('audit empty secret', () => {
  const r = new ConstantCompareGuard().auditInputs('', '')
  assert.ok(reasons(r).includes(CC_REASON.EMPTY_SECRET))
})

test('identical equal-length inputs pass audit and equals', () => {
  const g = new ConstantCompareGuard()
  const r = g.auditInputs('same', 'same')
  assert.equal(r.safe, true)
  assert.equal(g.equals('same', 'same'), true)
})

test('unicode code-unit comparison', () => {
  assert.equal(timingSafeEqualString('你好', '你好'), true)
  assert.equal(timingSafeEqualString('你好', '你坏'), false)
})
