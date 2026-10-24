'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T30Classify, E69T30_CLASS, E69T30_BLOCK, E69T30_WARN, E69T30_ALLOW } = require('./e69cjkcompatibilitycatalogguard.js')

test('E69T30 block classification', () => {
  for (const v of E69T30_BLOCK) assert.equal(E69T30Classify(v), E69T30_CLASS.BLOCK, v)
})

test('E69T30 warn classification', () => {
  for (const v of E69T30_WARN) assert.equal(E69T30Classify(v), E69T30_CLASS.WARN, v)
})

test('E69T30 allow classification', () => {
  for (const v of E69T30_ALLOW) assert.equal(E69T30Classify(v), E69T30_CLASS.ALLOW, v)
})

test('E69T30 unknown classification', () => {
  assert.equal(E69T30Classify('zzz-not-in-any-e69-catalog-88'), E69T30_CLASS.UNKNOWN)
})
