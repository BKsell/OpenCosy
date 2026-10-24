'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U04Classify, E70U04_CLASS, E70U04_BLOCK, E70U04_WARN, E70U04_ALLOW } = require('./e70ugariticcatalogguard.js')

test('E70U04 block classification', () => {
  for (const v of E70U04_BLOCK) assert.equal(E70U04Classify(v), E70U04_CLASS.BLOCK, v)
})

test('E70U04 warn classification', () => {
  for (const v of E70U04_WARN) assert.equal(E70U04Classify(v), E70U04_CLASS.WARN, v)
})

test('E70U04 allow classification', () => {
  for (const v of E70U04_ALLOW) assert.equal(E70U04Classify(v), E70U04_CLASS.ALLOW, v)
})

test('E70U04 unknown classification', () => {
  assert.equal(E70U04Classify('zzz-not-in-any-e70-catalog-99'), E70U04_CLASS.UNKNOWN)
})
