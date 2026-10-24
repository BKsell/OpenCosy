'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T16Classify, E69T16_CLASS, E69T16_BLOCK, E69T16_WARN, E69T16_ALLOW } = require('./e69copticcatalogguard.js')

test('E69T16 block classification', () => {
  for (const v of E69T16_BLOCK) assert.equal(E69T16Classify(v), E69T16_CLASS.BLOCK, v)
})

test('E69T16 warn classification', () => {
  for (const v of E69T16_WARN) assert.equal(E69T16Classify(v), E69T16_CLASS.WARN, v)
})

test('E69T16 allow classification', () => {
  for (const v of E69T16_ALLOW) assert.equal(E69T16Classify(v), E69T16_CLASS.ALLOW, v)
})

test('E69T16 unknown classification', () => {
  assert.equal(E69T16Classify('zzz-not-in-any-e69-catalog-88'), E69T16_CLASS.UNKNOWN)
})
