'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69U04Classify, E69U04_CLASS, E69U04_BLOCK, E69U04_WARN, E69U04_ALLOW } = require('./e69regionalindicatorscatalogguard.js')

test('E69U04 block classification', () => {
  for (const v of E69U04_BLOCK) assert.equal(E69U04Classify(v), E69U04_CLASS.BLOCK, v)
})

test('E69U04 warn classification', () => {
  for (const v of E69U04_WARN) assert.equal(E69U04Classify(v), E69U04_CLASS.WARN, v)
})

test('E69U04 allow classification', () => {
  for (const v of E69U04_ALLOW) assert.equal(E69U04Classify(v), E69U04_CLASS.ALLOW, v)
})

test('E69U04 unknown classification', () => {
  assert.equal(E69U04Classify('zzz-not-in-any-e69-catalog-88'), E69U04_CLASS.UNKNOWN)
})
