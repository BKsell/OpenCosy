'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T00Classify, E69T00_CLASS, E69T00_BLOCK, E69T00_WARN, E69T00_ALLOW } = require('./e69latin1supplementcatalogguard.js')

test('E69T00 block classification', () => {
  for (const v of E69T00_BLOCK) assert.equal(E69T00Classify(v), E69T00_CLASS.BLOCK, v)
})

test('E69T00 warn classification', () => {
  for (const v of E69T00_WARN) assert.equal(E69T00Classify(v), E69T00_CLASS.WARN, v)
})

test('E69T00 allow classification', () => {
  for (const v of E69T00_ALLOW) assert.equal(E69T00Classify(v), E69T00_CLASS.ALLOW, v)
})

test('E69T00 unknown classification', () => {
  assert.equal(E69T00Classify('zzz-not-in-any-e69-catalog-88'), E69T00_CLASS.UNKNOWN)
})
