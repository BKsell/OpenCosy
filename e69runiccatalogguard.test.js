'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T12Classify, E69T12_CLASS, E69T12_BLOCK, E69T12_WARN, E69T12_ALLOW } = require('./e69runiccatalogguard.js')

test('E69T12 block classification', () => {
  for (const v of E69T12_BLOCK) assert.equal(E69T12Classify(v), E69T12_CLASS.BLOCK, v)
})

test('E69T12 warn classification', () => {
  for (const v of E69T12_WARN) assert.equal(E69T12Classify(v), E69T12_CLASS.WARN, v)
})

test('E69T12 allow classification', () => {
  for (const v of E69T12_ALLOW) assert.equal(E69T12Classify(v), E69T12_CLASS.ALLOW, v)
})

test('E69T12 unknown classification', () => {
  assert.equal(E69T12Classify('zzz-not-in-any-e69-catalog-88'), E69T12_CLASS.UNKNOWN)
})
