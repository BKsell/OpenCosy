'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T11Classify, E69T11_CLASS, E69T11_BLOCK, E69T11_WARN, E69T11_ALLOW } = require('./e69oghamcatalogguard.js')

test('E69T11 block classification', () => {
  for (const v of E69T11_BLOCK) assert.equal(E69T11Classify(v), E69T11_CLASS.BLOCK, v)
})

test('E69T11 warn classification', () => {
  for (const v of E69T11_WARN) assert.equal(E69T11Classify(v), E69T11_CLASS.WARN, v)
})

test('E69T11 allow classification', () => {
  for (const v of E69T11_ALLOW) assert.equal(E69T11Classify(v), E69T11_CLASS.ALLOW, v)
})

test('E69T11 unknown classification', () => {
  assert.equal(E69T11Classify('zzz-not-in-any-e69-catalog-88'), E69T11_CLASS.UNKNOWN)
})
