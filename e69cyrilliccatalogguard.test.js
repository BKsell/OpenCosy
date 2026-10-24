'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T07Classify, E69T07_CLASS, E69T07_BLOCK, E69T07_WARN, E69T07_ALLOW } = require('./e69cyrilliccatalogguard.js')

test('E69T07 block classification', () => {
  for (const v of E69T07_BLOCK) assert.equal(E69T07Classify(v), E69T07_CLASS.BLOCK, v)
})

test('E69T07 warn classification', () => {
  for (const v of E69T07_WARN) assert.equal(E69T07Classify(v), E69T07_CLASS.WARN, v)
})

test('E69T07 allow classification', () => {
  for (const v of E69T07_ALLOW) assert.equal(E69T07Classify(v), E69T07_CLASS.ALLOW, v)
})

test('E69T07 unknown classification', () => {
  assert.equal(E69T07Classify('zzz-not-in-any-e69-catalog-88'), E69T07_CLASS.UNKNOWN)
})
