'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T25Classify, E69T25_CLASS, E69T25_BLOCK, E69T25_WARN, E69T25_ALLOW } = require('./e69hiraganacatalogguard.js')

test('E69T25 block classification', () => {
  for (const v of E69T25_BLOCK) assert.equal(E69T25Classify(v), E69T25_CLASS.BLOCK, v)
})

test('E69T25 warn classification', () => {
  for (const v of E69T25_WARN) assert.equal(E69T25Classify(v), E69T25_CLASS.WARN, v)
})

test('E69T25 allow classification', () => {
  for (const v of E69T25_ALLOW) assert.equal(E69T25Classify(v), E69T25_CLASS.ALLOW, v)
})

test('E69T25 unknown classification', () => {
  assert.equal(E69T25Classify('zzz-not-in-any-e69-catalog-88'), E69T25_CLASS.UNKNOWN)
})
