'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T20Classify, E69T20_CLASS, E69T20_BLOCK, E69T20_WARN, E69T20_ALLOW } = require('./e69kangxiradicalscatalogguard.js')

test('E69T20 block classification', () => {
  for (const v of E69T20_BLOCK) assert.equal(E69T20Classify(v), E69T20_CLASS.BLOCK, v)
})

test('E69T20 warn classification', () => {
  for (const v of E69T20_WARN) assert.equal(E69T20Classify(v), E69T20_CLASS.WARN, v)
})

test('E69T20 allow classification', () => {
  for (const v of E69T20_ALLOW) assert.equal(E69T20Classify(v), E69T20_CLASS.ALLOW, v)
})

test('E69T20 unknown classification', () => {
  assert.equal(E69T20Classify('zzz-not-in-any-e69-catalog-88'), E69T20_CLASS.UNKNOWN)
})
