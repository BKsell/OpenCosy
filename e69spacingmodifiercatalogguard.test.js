'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T04Classify, E69T04_CLASS, E69T04_BLOCK, E69T04_WARN, E69T04_ALLOW } = require('./e69spacingmodifiercatalogguard.js')

test('E69T04 block classification', () => {
  for (const v of E69T04_BLOCK) assert.equal(E69T04Classify(v), E69T04_CLASS.BLOCK, v)
})

test('E69T04 warn classification', () => {
  for (const v of E69T04_WARN) assert.equal(E69T04Classify(v), E69T04_CLASS.WARN, v)
})

test('E69T04 allow classification', () => {
  for (const v of E69T04_ALLOW) assert.equal(E69T04Classify(v), E69T04_CLASS.ALLOW, v)
})

test('E69T04 unknown classification', () => {
  assert.equal(E69T04Classify('zzz-not-in-any-e69-catalog-88'), E69T04_CLASS.UNKNOWN)
})
