'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T42Classify, E69T42_CLASS, E69T42_BLOCK, E69T42_WARN, E69T42_ALLOW } = require('./e69phoeniciancatalogguard.js')

test('E69T42 block classification', () => {
  for (const v of E69T42_BLOCK) assert.equal(E69T42Classify(v), E69T42_CLASS.BLOCK, v)
})

test('E69T42 warn classification', () => {
  for (const v of E69T42_WARN) assert.equal(E69T42Classify(v), E69T42_CLASS.WARN, v)
})

test('E69T42 allow classification', () => {
  for (const v of E69T42_ALLOW) assert.equal(E69T42Classify(v), E69T42_CLASS.ALLOW, v)
})

test('E69T42 unknown classification', () => {
  assert.equal(E69T42Classify('zzz-not-in-any-e69-catalog-88'), E69T42_CLASS.UNKNOWN)
})
