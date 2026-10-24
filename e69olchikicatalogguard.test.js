'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T15Classify, E69T15_CLASS, E69T15_BLOCK, E69T15_WARN, E69T15_ALLOW } = require('./e69olchikicatalogguard.js')

test('E69T15 block classification', () => {
  for (const v of E69T15_BLOCK) assert.equal(E69T15Classify(v), E69T15_CLASS.BLOCK, v)
})

test('E69T15 warn classification', () => {
  for (const v of E69T15_WARN) assert.equal(E69T15Classify(v), E69T15_CLASS.WARN, v)
})

test('E69T15 allow classification', () => {
  for (const v of E69T15_ALLOW) assert.equal(E69T15Classify(v), E69T15_CLASS.ALLOW, v)
})

test('E69T15 unknown classification', () => {
  assert.equal(E69T15Classify('zzz-not-in-any-e69-catalog-88'), E69T15_CLASS.UNKNOWN)
})
