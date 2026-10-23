'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { P32Classify, P32_CLASS, P32_BLOCK, P32_WARN, P32_ALLOW } = require('./privateuse3catalogguard.js')

test('P32 block classification', () => {
  for (const v of P32_BLOCK) assert.equal(P32Classify(v), P32_CLASS.BLOCK, v)
})

test('P32 warn classification', () => {
  for (const v of P32_WARN) assert.equal(P32Classify(v), P32_CLASS.WARN, v)
})

test('P32 allow classification', () => {
  for (const v of P32_ALLOW) assert.equal(P32Classify(v), P32_CLASS.ALLOW, v)
})

test('P32 unknown classification', () => {
  assert.equal(P32Classify('zzz-not-in-catalog-11'), P32_CLASS.UNKNOWN)
})
