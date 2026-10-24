'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T18Classify, E69T18_CLASS, E69T18_BLOCK, E69T18_WARN, E69T18_ALLOW } = require('./e69cyrillicextacatalogguard.js')

test('E69T18 block classification', () => {
  for (const v of E69T18_BLOCK) assert.equal(E69T18Classify(v), E69T18_CLASS.BLOCK, v)
})

test('E69T18 warn classification', () => {
  for (const v of E69T18_WARN) assert.equal(E69T18Classify(v), E69T18_CLASS.WARN, v)
})

test('E69T18 allow classification', () => {
  for (const v of E69T18_ALLOW) assert.equal(E69T18Classify(v), E69T18_CLASS.ALLOW, v)
})

test('E69T18 unknown classification', () => {
  assert.equal(E69T18Classify('zzz-not-in-any-e69-catalog-88'), E69T18_CLASS.UNKNOWN)
})
