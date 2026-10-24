'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U12Classify, E70U12_CLASS, E70U12_BLOCK, E70U12_WARN, E70U12_ALLOW } = require('./e70mathalnum3catalogguard.js')

test('E70U12 block classification', () => {
  for (const v of E70U12_BLOCK) assert.equal(E70U12Classify(v), E70U12_CLASS.BLOCK, v)
})

test('E70U12 warn classification', () => {
  for (const v of E70U12_WARN) assert.equal(E70U12Classify(v), E70U12_CLASS.WARN, v)
})

test('E70U12 allow classification', () => {
  for (const v of E70U12_ALLOW) assert.equal(E70U12Classify(v), E70U12_CLASS.ALLOW, v)
})

test('E70U12 unknown classification', () => {
  assert.equal(E70U12Classify('zzz-not-in-any-e70-catalog-99'), E70U12_CLASS.UNKNOWN)
})
