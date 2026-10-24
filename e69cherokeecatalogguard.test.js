'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T10Classify, E69T10_CLASS, E69T10_BLOCK, E69T10_WARN, E69T10_ALLOW } = require('./e69cherokeecatalogguard.js')

test('E69T10 block classification', () => {
  for (const v of E69T10_BLOCK) assert.equal(E69T10Classify(v), E69T10_CLASS.BLOCK, v)
})

test('E69T10 warn classification', () => {
  for (const v of E69T10_WARN) assert.equal(E69T10Classify(v), E69T10_CLASS.WARN, v)
})

test('E69T10 allow classification', () => {
  for (const v of E69T10_ALLOW) assert.equal(E69T10Classify(v), E69T10_CLASS.ALLOW, v)
})

test('E69T10 unknown classification', () => {
  assert.equal(E69T10Classify('zzz-not-in-any-e69-catalog-88'), E69T10_CLASS.UNKNOWN)
})
