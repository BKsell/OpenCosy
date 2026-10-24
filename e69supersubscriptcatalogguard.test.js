'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T22Classify, E69T22_CLASS, E69T22_BLOCK, E69T22_WARN, E69T22_ALLOW } = require('./e69supersubscriptcatalogguard.js')

test('E69T22 block classification', () => {
  for (const v of E69T22_BLOCK) assert.equal(E69T22Classify(v), E69T22_CLASS.BLOCK, v)
})

test('E69T22 warn classification', () => {
  for (const v of E69T22_WARN) assert.equal(E69T22Classify(v), E69T22_CLASS.WARN, v)
})

test('E69T22 allow classification', () => {
  for (const v of E69T22_ALLOW) assert.equal(E69T22Classify(v), E69T22_CLASS.ALLOW, v)
})

test('E69T22 unknown classification', () => {
  assert.equal(E69T22Classify('zzz-not-in-any-e69-catalog-88'), E69T22_CLASS.UNKNOWN)
})
