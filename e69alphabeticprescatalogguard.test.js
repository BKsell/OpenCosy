'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T33Classify, E69T33_CLASS, E69T33_BLOCK, E69T33_WARN, E69T33_ALLOW } = require('./e69alphabeticprescatalogguard.js')

test('E69T33 block classification', () => {
  for (const v of E69T33_BLOCK) assert.equal(E69T33Classify(v), E69T33_CLASS.BLOCK, v)
})

test('E69T33 warn classification', () => {
  for (const v of E69T33_WARN) assert.equal(E69T33Classify(v), E69T33_CLASS.WARN, v)
})

test('E69T33 allow classification', () => {
  for (const v of E69T33_ALLOW) assert.equal(E69T33Classify(v), E69T33_CLASS.ALLOW, v)
})

test('E69T33 unknown classification', () => {
  assert.equal(E69T33Classify('zzz-not-in-any-e69-catalog-88'), E69T33_CLASS.UNKNOWN)
})
