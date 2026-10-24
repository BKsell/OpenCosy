'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T28Classify, E69T28_CLASS, E69T28_BLOCK, E69T28_WARN, E69T28_ALLOW } = require('./e69hangulcompatjamocatalogguard.js')

test('E69T28 block classification', () => {
  for (const v of E69T28_BLOCK) assert.equal(E69T28Classify(v), E69T28_CLASS.BLOCK, v)
})

test('E69T28 warn classification', () => {
  for (const v of E69T28_WARN) assert.equal(E69T28Classify(v), E69T28_CLASS.WARN, v)
})

test('E69T28 allow classification', () => {
  for (const v of E69T28_ALLOW) assert.equal(E69T28Classify(v), E69T28_CLASS.ALLOW, v)
})

test('E69T28 unknown classification', () => {
  assert.equal(E69T28Classify('zzz-not-in-any-e69-catalog-88'), E69T28_CLASS.UNKNOWN)
})
