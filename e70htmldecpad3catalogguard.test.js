'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70HD3Classify, E70HD3_CLASS, E70HD3_BLOCK, E70HD3_WARN, E70HD3_ALLOW } = require('./e70htmldecpad3catalogguard.js')

test('E70HD3 block classification', () => {
  for (const v of E70HD3_BLOCK) assert.equal(E70HD3Classify(v), E70HD3_CLASS.BLOCK, v)
})

test('E70HD3 warn classification', () => {
  for (const v of E70HD3_WARN) assert.equal(E70HD3Classify(v), E70HD3_CLASS.WARN, v)
})

test('E70HD3 allow classification', () => {
  for (const v of E70HD3_ALLOW) assert.equal(E70HD3Classify(v), E70HD3_CLASS.ALLOW, v)
})

test('E70HD3 unknown classification', () => {
  assert.equal(E70HD3Classify('zzz-not-in-any-e70-catalog-99'), E70HD3_CLASS.UNKNOWN)
})
