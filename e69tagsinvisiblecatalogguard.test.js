'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U06Classify, E69U06_CLASS, E69U06_BLOCK, E69U06_WARN, E69U06_ALLOW } = require('./e69tagsinvisiblecatalogguard.js')

test('E69U06 block classification', () => {
  for (const v of E69U06_BLOCK) assert.equal(E69U06Classify(v), E69U06_CLASS.BLOCK, v)
})

test('E69U06 warn classification', () => {
  for (const v of E69U06_WARN) assert.equal(E69U06Classify(v), E69U06_CLASS.WARN, v)
})

test('E69U06 allow classification', () => {
  for (const v of E69U06_ALLOW) assert.equal(E69U06Classify(v), E69U06_CLASS.ALLOW, v)
})

test('E69U06 unknown classification', () => {
  assert.equal(E69U06Classify('zzz-not-in-any-e69-catalog-88'), E69U06_CLASS.UNKNOWN)
})
