'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T21Classify, E69T21_CLASS, E69T21_BLOCK, E69T21_WARN, E69T21_ALLOW } = require('./e69generalpunctuationcatalogguard.js')

test('E69T21 block classification', () => {
  for (const v of E69T21_BLOCK) assert.equal(E69T21Classify(v), E69T21_CLASS.BLOCK, v)
})

test('E69T21 warn classification', () => {
  for (const v of E69T21_WARN) assert.equal(E69T21Classify(v), E69T21_CLASS.WARN, v)
})

test('E69T21 allow classification', () => {
  for (const v of E69T21_ALLOW) assert.equal(E69T21Classify(v), E69T21_CLASS.ALLOW, v)
})

test('E69T21 unknown classification', () => {
  assert.equal(E69T21Classify('zzz-not-in-any-e69-catalog-88'), E69T21_CLASS.UNKNOWN)
})
