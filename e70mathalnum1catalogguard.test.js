'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U10Classify, E70U10_CLASS, E70U10_BLOCK, E70U10_WARN, E70U10_ALLOW } = require('./e70mathalnum1catalogguard.js')

test('E70U10 block classification', () => {
  for (const v of E70U10_BLOCK) assert.equal(E70U10Classify(v), E70U10_CLASS.BLOCK, v)
})

test('E70U10 warn classification', () => {
  for (const v of E70U10_WARN) assert.equal(E70U10Classify(v), E70U10_CLASS.WARN, v)
})

test('E70U10 allow classification', () => {
  for (const v of E70U10_ALLOW) assert.equal(E70U10Classify(v), E70U10_CLASS.ALLOW, v)
})

test('E70U10 unknown classification', () => {
  assert.equal(E70U10Classify('zzz-not-in-any-e70-catalog-99'), E70U10_CLASS.UNKNOWN)
})
