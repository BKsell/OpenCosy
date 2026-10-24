'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70T41Classify, E70T41_CLASS, E70T41_BLOCK, E70T41_WARN, E70T41_ALLOW } = require('./e70mathoperatorscatalogguard.js')

test('E70T41 block classification', () => {
  for (const v of E70T41_BLOCK) assert.equal(E70T41Classify(v), E70T41_CLASS.BLOCK, v)
})

test('E70T41 warn classification', () => {
  for (const v of E70T41_WARN) assert.equal(E70T41Classify(v), E70T41_CLASS.WARN, v)
})

test('E70T41 allow classification', () => {
  for (const v of E70T41_ALLOW) assert.equal(E70T41Classify(v), E70T41_CLASS.ALLOW, v)
})

test('E70T41 unknown classification', () => {
  assert.equal(E70T41Classify('zzz-not-in-any-e70-catalog-99'), E70T41_CLASS.UNKNOWN)
})
