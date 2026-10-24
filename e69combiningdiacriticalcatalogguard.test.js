'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

const { E69T05Classify, E69T05_CLASS, E69T05_BLOCK, E69T05_WARN, E69T05_ALLOW } = require('./e69combiningdiacriticalcatalogguard.js')

test('E69T05 block classification', () => {
  for (const v of E69T05_BLOCK) assert.equal(E69T05Classify(v), E69T05_CLASS.BLOCK, v)
})

test('E69T05 warn classification', () => {
  for (const v of E69T05_WARN) assert.equal(E69T05Classify(v), E69T05_CLASS.WARN, v)
})

test('E69T05 allow classification', () => {
  for (const v of E69T05_ALLOW) assert.equal(E69T05Classify(v), E69T05_CLASS.ALLOW, v)
})

test('E69T05 unknown classification', () => {
  assert.equal(E69T05Classify('zzz-not-in-any-e69-catalog-88'), E69T05_CLASS.UNKNOWN)
})
