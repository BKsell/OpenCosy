'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { JsonBodyGuard, JB_REASON, jbValidNumber } = require('./jsonbodyguard.js')

function reasons (text, policy) {
  return new JsonBodyGuard(policy).parse(text).findings.map((f) => f.reason)
}

test('valid object parses', () => {
  const r = new JsonBodyGuard().parse('{"a":1,"b":[true,null]}')
  assert.equal(r.safe, true)
  assert.equal(r.value.a, 1)
})

test('duplicate key flagged', () => {
  assert.ok(reasons('{"role":"user","role":"admin"}').includes(JB_REASON.DUPLICATE_KEY))
})

test('unicode-escaped duplicate key still flagged', () => {
  // "role" 与 "r\u006fle" 语义相同
  assert.ok(reasons('{"role":1,"r\\u006fle":2}').includes(JB_REASON.DUPLICATE_KEY))
})

test('same key in different objects ok', () => {
  assert.equal(new JsonBodyGuard().parse('{"a":{"k":1},"b":{"k":2}}').safe, true)
})

test('deep nesting flagged', () => {
  let s = ''
  for (let i = 0; i < 40; i++) s += '['
  for (let i = 0; i < 40; i++) s += ']'
  assert.ok(reasons(s, { maxDepth: 32 }).includes(JB_REASON.NESTING_DEEP))
})

test('oversize body flagged and not parsed', () => {
  const r = new JsonBodyGuard({ maxBytes: 5 }).parse('{"a":1}')
  assert.ok(r.findings.some((f) => f.reason === JB_REASON.TOO_LARGE))
  assert.equal(r.value, undefined)
})

test('overlong string flagged', () => {
  const big = 'x'.repeat(100)
  assert.ok(reasons('{"s":"' + big + '"}', { maxStringLength: 10 }).includes(JB_REASON.STRING_OVERLONG))
})

test('malformed json flagged', () => {
  assert.ok(reasons('{"a":}').includes(JB_REASON.PARSE_FAILED))
})

test('bad number flagged', () => {
  assert.ok(reasons('{"a":01}').includes(JB_REASON.NUMBER_INVALID))
})

test('number lexer unit checks', () => {
  assert.equal(jbValidNumber('12'), true)
  assert.equal(jbValidNumber('-0.5e-3'), true)
  assert.equal(jbValidNumber('1.'), false)
  assert.equal(jbValidNumber('01'), false)
  assert.equal(jbValidNumber('1e'), false)
})

test('valid array root', () => {
  assert.equal(new JsonBodyGuard().parse('[1,2,3]').safe, true)
})

test('nested containers parse correctly', () => {
  const r = new JsonBodyGuard().parse('{"a":{"b":[1,{"c":2}]}}')
  assert.equal(r.value.a.b[1].c, 2)
})
