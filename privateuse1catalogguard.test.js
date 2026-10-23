'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { P12Classify, P12_CLASS, P12_BLOCK, P12_WARN, P12_ALLOW } = require('./privateuse1catalogguard.js')

test('P12 block classification', () => {
  for (const v of P12_BLOCK) assert.equal(P12Classify(v), P12_CLASS.BLOCK, v)
})

test('P12 warn classification', () => {
  for (const v of P12_WARN) assert.equal(P12Classify(v), P12_CLASS.WARN, v)
})

test('P12 allow classification', () => {
  for (const v of P12_ALLOW) assert.equal(P12Classify(v), P12_CLASS.ALLOW, v)
})

test('P12 unknown classification', () => {
  assert.equal(P12Classify('zzz-not-in-catalog-11'), P12_CLASS.UNKNOWN)
})
