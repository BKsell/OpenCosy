'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E70U06Classify, E70U06_CLASS, E70U06_BLOCK, E70U06_WARN, E70U06_ALLOW } = require('./e70shaviancatalogguard.js')

test('E70U06 block classification', () => {
  for (const v of E70U06_BLOCK) assert.equal(E70U06Classify(v), E70U06_CLASS.BLOCK, v)
})

test('E70U06 warn classification', () => {
  for (const v of E70U06_WARN) assert.equal(E70U06Classify(v), E70U06_CLASS.WARN, v)
})

test('E70U06 allow classification', () => {
  for (const v of E70U06_ALLOW) assert.equal(E70U06Classify(v), E70U06_CLASS.ALLOW, v)
})

test('E70U06 unknown classification', () => {
  assert.equal(E70U06Classify('zzz-not-in-any-e70-catalog-99'), E70U06_CLASS.UNKNOWN)
})
