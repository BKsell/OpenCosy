'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T37Classify, E69T37_CLASS, E69T37_BLOCK, E69T37_WARN, E69T37_ALLOW } = require('./e69combiningextcatalogguard.js')

test('E69T37 block classification', () => {
  for (const v of E69T37_BLOCK) assert.equal(E69T37Classify(v), E69T37_CLASS.BLOCK, v)
})

test('E69T37 warn classification', () => {
  for (const v of E69T37_WARN) assert.equal(E69T37Classify(v), E69T37_CLASS.WARN, v)
})

test('E69T37 allow classification', () => {
  for (const v of E69T37_ALLOW) assert.equal(E69T37Classify(v), E69T37_CLASS.ALLOW, v)
})

test('E69T37 unknown classification', () => {
  assert.equal(E69T37Classify('zzz-not-in-any-e69-catalog-88'), E69T37_CLASS.UNKNOWN)
})
