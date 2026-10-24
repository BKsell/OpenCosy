'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T17Classify, E69T17_CLASS, E69T17_BLOCK, E69T17_WARN, E69T17_ALLOW } = require('./e69tifinaghcatalogguard.js')

test('E69T17 block classification', () => {
  for (const v of E69T17_BLOCK) assert.equal(E69T17Classify(v), E69T17_CLASS.BLOCK, v)
})

test('E69T17 warn classification', () => {
  for (const v of E69T17_WARN) assert.equal(E69T17Classify(v), E69T17_CLASS.WARN, v)
})

test('E69T17 allow classification', () => {
  for (const v of E69T17_ALLOW) assert.equal(E69T17Classify(v), E69T17_CLASS.ALLOW, v)
})

test('E69T17 unknown classification', () => {
  assert.equal(E69T17Classify('zzz-not-in-any-e69-catalog-88'), E69T17_CLASS.UNKNOWN)
})
